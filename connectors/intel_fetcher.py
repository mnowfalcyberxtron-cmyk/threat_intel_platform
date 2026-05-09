"""
connectors/intel_fetcher.py — Live Threat Intelligence Feed Fetcher.
Runs every 5 minutes. Fetches latest blogs, advisories, and malware reports.
Stores articles in intel_feed table so AI can use fresh context.

Sources:
- BleepingComputer, The Hacker News, Krebs, SANS ISC
- CISA alerts, Unit42, Secureworks, Recorded Future
- Malware-specific: vx-underground, abuse.ch blog
- CVE feeds: NVD, CISA KEV new entries
- Twitter/X threat intel (via nitter RSS mirrors)
"""

import re
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, now_iso

try:
    import feedparser
    HAS_FP = True
except ImportError:
    HAS_FP = False

# 5-minute intel feeds — fastest-updating, most relevant
FAST_FEEDS = [
    {"name": "The Hacker News",     "url": "https://feeds.feedburner.com/TheHackersNews",           "category": "threat_news"},
    {"name": "Bleeping Computer",   "url": "https://www.bleepingcomputer.com/feed/",                 "category": "threat_news"},
    {"name": "CISA Alerts",         "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",            "category": "advisory"},
    {"name": "SANS ISC",            "url": "https://isc.sans.edu/rssfeed_full.xml",                  "category": "advisory"},
    {"name": "Krebs on Security",   "url": "https://krebsonsecurity.com/feed/",                      "category": "threat_news"},
    {"name": "Unit 42",             "url": "https://unit42.paloaltonetworks.com/feed/",              "category": "malware_analysis"},
    {"name": "Secureworks CTU",     "url": "https://www.secureworks.com/rss/research",               "category": "threat_actor"},
    {"name": "Recorded Future",     "url": "https://www.recordedfuture.com/feed",                    "category": "threat_intel"},
    {"name": "Malwarebytes Blog",   "url": "https://www.malwarebytes.com/blog/feed/",                "category": "malware_analysis"},
    {"name": "Trend Micro",         "url": "https://feeds.trendmicro.com/Anti-Malware-Research",     "category": "malware_analysis"},
    {"name": "Microsoft MSRC",      "url": "https://api.msrc.microsoft.com/update-guide/rss",        "category": "vulnerability"},
    {"name": "NVDB NVD CVE",        "url": "https://feeds.feedburner.com/nvd/CVE-Recent",            "category": "vulnerability"},
    {"name": "Cisco Talos",         "url": "https://blog.talosintelligence.com/feeds/posts/default", "category": "threat_intel"},
    {"name": "Mandiant",            "url": "https://www.mandiant.com/resources/blog/rss.xml",        "category": "threat_actor"},
    {"name": "Sekoia TDR",          "url": "https://blog.sekoia.io/feed/",                           "category": "threat_actor"},
    {"name": "Elastic Security",    "url": "https://www.elastic.co/security-labs/rss/feed.xml",      "category": "malware_analysis"},
]

# TI-relevant keywords for relevance scoring
HIGH_RELEVANCE_KEYWORDS = [
    "ransomware", "apt", "threat actor", "zero-day", "cve-", "malware",
    "backdoor", "c2", "command and control", "data breach", "exploit",
    "lockbit", "blackcat", "alphv", "cl0p", "akira", "rhysida", "play",
    "emotet", "qakbot", "icedid", "cobalt strike", "metasploit",
    "stealer", "infostealer", "redline", "lumma", "rhadamanthys",
    "phishing", "spearphishing", "supply chain", "lolbas", "living off the land",
    "lateral movement", "privilege escalation", "persistence",
    "mitre att&ck", "ttps", "ioc", "indicator of compromise",
    "nation-state", "chinese apt", "russian apt", "north korean", "iranian",
    "lazarus", "fancy bear", "cozy bear", "sandworm", "volt typhoon",
    "scattered spider", "lapsus", "darkside", "revil", "conti",
]


class IntelFetcherConnector(BaseConnector):
    """
    Fast 5-minute threat intelligence feed fetcher.
    Stores articles in intel_feed table for AI context injection.
    Does NOT produce IOC records — produces intel_feed records.
    """
    name = "intel_fetcher"
    display_name = "Live TI Feed (5min)"
    tier = 1

    async def fetch(self) -> List[Dict[str, Any]]:
        """Fetch from all feeds. Returns empty list (stores directly via db)."""
        # This connector stores to DB directly via the scheduler
        # Returns special type="intel" records
        if not HAS_FP:
            self.logger.warning("feedparser not installed")
            return []

        records = []
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        for feed_cfg in FAST_FEEDS:
            try:
                articles = await self._fetch_feed(feed_cfg, cutoff)
                records.extend(articles)
            except Exception as e:
                self.logger.debug("Feed %s: %s", feed_cfg["name"], e)

        self.logger.info("IntelFetcher: %d new articles", len(records))
        return records

    async def _fetch_feed(self, cfg: dict, cutoff: str) -> List[Dict]:
        text = await self._get(cfg["url"], headers={"User-Agent": "CyberXTron-TIP/2.2"})
        if not text or not isinstance(text, str):
            return []

        feed = feedparser.parse(text)
        records = []

        for entry in feed.entries[:15]:  # 15 most recent per feed
            title   = (getattr(entry, "title", "") or "").strip()
            link    = (getattr(entry, "link", "") or "").strip()
            summary = (getattr(entry, "summary", "") or
                       getattr(entry, "description", "") or "").strip()

            # Strip HTML from summary
            summary = re.sub(r"<[^>]+>", " ", summary)
            summary = re.sub(r"\s+", " ", summary).strip()[:800]

            if not title or not link:
                continue

            # Parse date
            pub_date = now_iso()
            try:
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    from datetime import datetime as dt
                    pub_date = dt(*entry.published_parsed[:6], tzinfo=timezone.utc).isoformat()
            except Exception:
                pass

            # Skip old articles
            if pub_date < cutoff:
                continue

            # Relevance score
            text_lower = (title + " " + summary).lower()
            relevance  = self._score_relevance(text_lower)

            # Extract tags
            tags = self._extract_tags(text_lower)

            records.append({
                "type":        "intel",
                "title":       title,
                "summary":     summary,
                "url":         link,
                "source_name": cfg["name"],
                "category":    cfg["category"],
                "published":   pub_date,
                "tags":        tags,
                "relevance":   relevance,
            })

        return sorted(records, key=lambda x: x["relevance"], reverse=True)

    def _score_relevance(self, text: str) -> float:
        """Score 0-1 based on TI keyword density."""
        hits = sum(1 for kw in HIGH_RELEVANCE_KEYWORDS if kw in text)
        return min(round(hits / max(len(HIGH_RELEVANCE_KEYWORDS) * 0.3, 1), 3), 1.0)

    def _extract_tags(self, text: str) -> List[str]:
        tags = []
        # CVEs
        tags.extend(re.findall(r"cve-\d{4}-\d{4,7}", text, re.I))
        # Group names
        GROUPS = ["lockbit","blackcat","alphv","cl0p","akira","rhysida","play",
                  "medusa","hunters","bianlian","darkside","revil","conti",
                  "lazarus","fancy bear","cozy bear","volt typhoon","scattered spider"]
        for g in GROUPS:
            if g in text: tags.append(g)
        # Malware families
        MALWARE = ["emotet","qakbot","icedid","cobalt strike","metasploit","redline",
                   "lumma","rhadamanthys","asyncrat","njrat","nanocore"]
        for m in MALWARE:
            if m in text: tags.append(m)
        return list(set(tags))[:10]
