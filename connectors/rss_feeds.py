"""
connectors/rss_feeds.py — RSS Threat Intelligence Feeds connector.
Ingests threat intel news and indicators from major security blogs and CERT feeds.
Extracts IOCs from article content where possible.
"""

import re
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

try:
    import feedparser
    HAS_FEEDPARSER = True
except ImportError:
    HAS_FEEDPARSER = False

from connectors.base import BaseConnector, now_iso
from config import settings


# Patterns for IOC extraction from text
PATTERNS = {
    "ip":     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|cc|pw|su|to)\b",
        re.IGNORECASE,
    ),
    "md5":    re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1":   re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "cve":    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    "url":    re.compile(r"https?://[^\s<>\"']+"),
}

# Known false-positive IPs / domains to skip
FP_IPS = {"0.0.0.0", "127.0.0.1", "8.8.8.8", "8.8.4.4", "1.1.1.1", "255.255.255.255"}
FP_DOMAINS = {
    "google.com", "microsoft.com", "example.com", "github.com",
    "twitter.com", "facebook.com", "youtube.com", "amazon.com",
    "cloudflare.com", "cisa.gov",
}


class RSSFeedsConnector(BaseConnector):
    name = "rss"
    display_name = "RSS Threat Intel Feeds"
    tier = 1

    async def fetch(self) -> List[Dict[str, Any]]:
        if not HAS_FEEDPARSER:
            self.logger.warning("feedparser not installed, skipping RSS connector")
            return []

        records = []
        for feed_config in settings.RSS_FEEDS:
            feed_name = feed_config["name"]
            feed_url = feed_config["url"]
            try:
                feed_records = await self._process_feed(feed_name, feed_url)
                records.extend(feed_records)
                self.logger.info(
                    "RSS feed '%s': %d records", feed_name, len(feed_records)
                )
            except Exception as e:
                self.logger.warning("RSS feed '%s' failed: %s", feed_name, e)

        return records

    async def _process_feed(self, feed_name: str, feed_url: str) -> List[Dict[str, Any]]:
        text = await self._get(feed_url)
        if not text or not isinstance(text, str):
            return []

        feed = feedparser.parse(text)
        records = []

        for entry in feed.entries[:20]:  # Limit to 20 most recent per feed
            title = getattr(entry, "title", "")
            link = getattr(entry, "link", "")
            summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
            published = getattr(entry, "published", now_iso())

            # Parse published date
            try:
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                    published = dt.isoformat()
            except Exception:
                pass

            # Combine title + summary for IOC extraction
            content = f"{title} {summary}"

            # Extract IOCs from content
            extracted = self._extract_iocs(content, feed_name, published)
            records.extend(extracted)

            # If we find CVEs — emit those as news/threat items too
            cves = re.findall(PATTERNS["cve"], content)
            for cve in set(cves):
                records.append(
                    self.make_ioc(
                        source=self.name,
                        ioc=cve.upper(),
                        ioc_type="cve",
                        tags=["cve", feed_name.lower().replace(" ", "_")],
                        confidence="low",
                        first_seen=published,
                        last_seen=published,
                        description=f"Mentioned in: {title[:120]} | Source: {feed_name}",
                        raw={"title": title, "link": link, "feed": feed_name},
                    )
                )

        return records

    def _extract_iocs(
        self, content: str, feed_name: str, published: str
    ) -> List[Dict[str, Any]]:
        records = []
        seen = set()

        # Defang common obfuscations: hxxp -> http, [.] -> .
        defanged = content
        defanged = re.sub(r"hxxps?", "http", defanged, flags=re.IGNORECASE)
        defanged = re.sub(r"\[\.\]", ".", defanged)
        defanged = re.sub(r"\[at\]", "@", defanged, flags=re.IGNORECASE)

        for ioc_type, pattern in PATTERNS.items():
            if ioc_type in ("cve", "url"):  # handled separately or too noisy
                continue

            for match in pattern.finditer(defanged):
                value = match.group().strip().lower()
                if value in seen:
                    continue
                if ioc_type == "ip" and value in FP_IPS:
                    continue
                if ioc_type == "domain" and value in FP_DOMAINS:
                    continue
                # Basic sanity: IPs must have valid octets
                if ioc_type == "ip":
                    parts = value.split(".")
                    if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        continue
                seen.add(value)
                records.append(
                    self.make_ioc(
                        source=self.name,
                        ioc=value,
                        ioc_type=ioc_type,
                        tags=[feed_name.lower().replace(" ", "_"), "rss_extracted"],
                        confidence="low",
                        first_seen=published,
                        last_seen=published,
                        description=f"Extracted from RSS feed: {feed_name}",
                    )
                )

        return records
