"""
connectors/web_intel.py — Real-time web threat intelligence collector.
Runs every 5 minutes. Fetches from:
  - Google News RSS (free, no key)
  - DuckDuckGo search (free, no key)
  - Reddit r/netsec, r/malware, r/threatintel (free JSON API)
  - Security blogs RSS (BleepingComputer, THN, SANS, etc.)
  - Feeds aggregated by category: malware, ransomware, APT, CVE

Stores in threat_feed table. AI reads this for context before responding.
"""

import re
import json
import hashlib
import asyncio
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, now_iso

# Known threat actor / malware keywords for relevance scoring
THREAT_KEYWORDS = {
    "critical": ["0-day","zero-day","rce","exploit","backdoor","apt","ransomware",
                 "lockbit","blackcat","clop","rhysida","akira","volt typhoon",
                 "lazarus","cozy bear","fancy bear","emotet","qakbot","cobalt strike",
                 "icedid","redline","stealc","formbook","njrat","asyncrat","darkgate"],
    "high":     ["malware","threat actor","data breach","cve-2024","cve-2025",
                 "vulnerability","phishing","infostealer","c2","botnet","trojan",
                 "campaign","attack","indicator","ioc","ttp","mitre"],
    "medium":   ["security","cyber","hack","breach","leak","stolen","credentials",
                 "patch","update","advisory","alert","warning","incident"],
}

# High-signal RSS feeds for threat intel
THREAT_RSS_FEEDS = [
    # Security blogs
    {"url":"https://www.bleepingcomputer.com/feed/","name":"BleepingComputer","cat":"news"},
    {"url":"https://feeds.feedburner.com/TheHackersNews","name":"The Hacker News","cat":"news"},
    {"url":"https://krebsonsecurity.com/feed/","name":"Krebs on Security","cat":"news"},
    {"url":"https://isc.sans.edu/rssfeed_full.xml","name":"SANS ISC","cat":"alerts"},
    {"url":"https://www.cisa.gov/uscert/ncas/alerts.xml","name":"CISA Alerts","cat":"alerts"},
    {"url":"https://unit42.paloaltonetworks.com/feed/","name":"Palo Alto Unit42","cat":"research"},
    {"url":"https://research.checkpoint.com/feed/","name":"Check Point Research","cat":"research"},
    {"url":"https://www.mandiant.com/resources/blog/rss.xml","name":"Mandiant Blog","cat":"research"},
    {"url":"https://securelist.com/feed/","name":"Kaspersky Securelist","cat":"research"},
    {"url":"https://www.welivesecurity.com/en/feed/","name":"ESET WeLiveSecurity","cat":"research"},
    {"url":"https://www.crowdstrike.com/blog/feed/","name":"CrowdStrike Blog","cat":"research"},
    {"url":"https://decoded.avast.io/feed/","name":"Avast Decoded","cat":"research"},
    {"url":"https://www.sentinelone.com/blog/feed/","name":"SentinelOne Blog","cat":"research"},
    {"url":"https://www.rapid7.com/blog/rss.xml","name":"Rapid7 Blog","cat":"research"},
    {"url":"https://blog.talosintelligence.com/feeds/posts/default","name":"Cisco Talos","cat":"research"},
]

# Google News RSS searches (no key needed)
GOOGLE_NEWS_SEARCHES = [
    "ransomware attack 2025",
    "APT threat actor 2025",
    "new malware discovered 2025",
    "cyber attack breach 2025",
    "zero day exploit 2025",
    "cybersecurity threat intelligence",
    "ransomware group victim",
]

# DuckDuckGo search queries (fallback external source when RSS/search feeds miss)
DUCKDUCKGO_SEARCHES = [
    "ransomware group victims leak site",
    "new malware campaign threat intelligence",
    "apt threat actor latest activity",
]

# Reddit subreddits with JSON API (no key needed)
REDDIT_SOURCES = [
    "https://www.reddit.com/r/netsec/new.json?limit=25",
    "https://www.reddit.com/r/Malware/new.json?limit=25",
    "https://www.reddit.com/r/cybersecurity/new.json?limit=25",
]


class WebIntelConnector(BaseConnector):
    """
    Real-time web threat intelligence collector.
    Runs every 5 minutes (300s) to keep AI context fresh.
    """
    name = "web_intel"
    display_name = "Web Threat Intel (Live Feed)"
    tier = 1

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CyberXTron-TIP/2.3 Threat Intelligence)",
            "Accept": "application/rss+xml, application/xml, text/xml, application/json, */*",
        }

        # 1. Threat Intel RSS feeds (most reliable)
        rss_items = await self._fetch_all_rss(headers)
        records.extend(rss_items)

        # 2. Google News RSS searches
        gnews_items = await self._fetch_google_news(headers)
        records.extend(gnews_items)

        # 3. DuckDuckGo web search fallback
        ddg_items = await self._fetch_duckduckgo(headers)
        records.extend(ddg_items)

        # 4. Reddit threat intel posts
        reddit_items = await self._fetch_reddit(headers)
        records.extend(reddit_items)

        # Deduplicate by URL
        seen_urls = set()
        deduped = []
        for r in records:
            url = r.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                deduped.append(r)

        # Sort by relevance
        deduped.sort(key=lambda x: x.get("relevance", 0), reverse=True)

        self.logger.info("WebIntel: %d unique items fetched", len(deduped))
        return deduped

    async def _fetch_all_rss(self, headers: dict) -> List[Dict]:
        tasks = [self._fetch_rss_feed(f["url"], f["name"], f["cat"], headers)
                 for f in THREAT_RSS_FEEDS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for r in results:
            if isinstance(r, list):
                out.extend(r)
        return out

    async def _fetch_rss_feed(self, url: str, name: str, cat: str, headers: dict) -> List[Dict]:
        text = await self._get(url, headers=headers)
        if not isinstance(text, str) or not text.strip():
            return []
        try:
            root = ET.fromstring(text)
        except Exception:
            return []

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = []

        # Handle both RSS and Atom
        for item in (root.findall(".//item") + root.findall(".//atom:entry", ns)):
            title   = self._xml_text(item, ["title"])
            link    = self._xml_text(item, ["link","atom:link"], ns) or \
                     (item.find("link") is not None and item.find("link").get("href","")) or ""
            summary = self._xml_text(item, ["description","summary","content","atom:summary"], ns)
            pubdate = self._xml_text(item, ["pubDate","published","updated","atom:published"], ns)

            if not title or not link: continue

            # Clean HTML from summary
            summary_clean = re.sub(r'<[^>]+>', ' ', summary or '')
            summary_clean = re.sub(r'\s+', ' ', summary_clean).strip()[:500]

            content = f"{title} {summary_clean}"
            relevance = self._score_relevance(content)
            entities  = self._extract_entities(content)
            category  = self._classify(content, cat)

            if relevance < 0.2: continue  # Skip irrelevant items

            items.append({
                "type": "feed_item",
                "title": title[:200],
                "summary": summary_clean,
                "url": link.strip(),
                "source": name,
                "source_type": "rss",
                "category": category,
                "entities": entities,
                "published": self._parse_date(pubdate),
                "fetched_at": now_iso(),
                "relevance": relevance,
            })

        return items[:20]  # Max 20 per feed

    async def _fetch_google_news(self, headers: dict) -> List[Dict]:
        items = []
        # Use only 3 searches to avoid overloading
        for query in GOOGLE_NEWS_SEARCHES[:3]:
            url = f"https://news.google.com/rss/search?q={query.replace(' ','+')}&hl=en-US&gl=US&ceid=US:en"
            text = await self._get(url, headers=headers)
            if not isinstance(text, str): continue
            try:
                root = ET.fromstring(text)
                for item in root.findall(".//item")[:5]:
                    title   = self._xml_text(item, ["title"])
                    link    = self._xml_text(item, ["link"])
                    summary = self._xml_text(item, ["description"])
                    pubdate = self._xml_text(item, ["pubDate"])
                    if not title or not link: continue
                    summary_clean = re.sub(r'<[^>]+>', ' ', summary or '').strip()[:300]
                    content   = f"{title} {summary_clean}"
                    relevance = self._score_relevance(content)
                    if relevance < 0.3: continue
                    items.append({
                        "type": "feed_item",
                        "title": title[:200],
                        "summary": summary_clean,
                        "url": link.strip(),
                        "source": f"Google News: {query}",
                        "source_type": "google_news",
                        "category": self._classify(content, "news"),
                        "entities": self._extract_entities(content),
                        "published": self._parse_date(pubdate),
                        "fetched_at": now_iso(),
                        "relevance": min(relevance + 0.1, 1.0),
                    })
            except Exception as e:
                self.logger.debug("GNews parse error: %s", e)
        return items

    async def _fetch_duckduckgo(self, headers: dict) -> List[Dict]:
        """
        Fetch external intel snippets from DuckDuckGo HTML results.
        Works as a resilient fallback when other external sources are sparse.
        """
        items = []
        for query in DUCKDUCKGO_SEARCHES:
            q = query.replace(" ", "+")
            url = f"https://duckduckgo.com/html/?q={q}"
            text = await self._get(url, headers=headers)
            if not isinstance(text, str) or not text.strip():
                continue
            try:
                # Extract href + title from DDG result anchors
                matches = re.findall(
                    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                    text,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                for href, title_html in matches[:8]:
                    title = re.sub(r"<[^>]+>", " ", title_html)
                    title = re.sub(r"\s+", " ", title).strip()
                    if not title:
                        continue
                    clean_url = href.strip()
                    # Skip DDG internal redirect links and non-http links
                    if not clean_url.startswith("http") or "duckduckgo.com/" in clean_url:
                        continue

                    content = title
                    relevance = self._score_relevance(content)
                    if relevance < 0.28:
                        continue

                    items.append({
                        "type": "feed_item",
                        "title": title[:200],
                        "summary": "",
                        "url": clean_url,
                        "source": f"DuckDuckGo: {query}",
                        "source_type": "duckduckgo",
                        "category": self._classify(content, "news"),
                        "entities": self._extract_entities(content),
                        "published": now_iso(),
                        "fetched_at": now_iso(),
                        "relevance": min(relevance + 0.05, 1.0),
                    })
            except Exception as e:
                self.logger.debug("DDG parse error: %s", e)
        return items

    async def _fetch_reddit(self, headers: dict) -> List[Dict]:
        rh = {**headers, "Accept": "application/json"}
        items = []
        for url in REDDIT_SOURCES[:2]:  # Limit to 2 subreddits
            data = await self._get(url, headers=rh)
            if not isinstance(data, dict): continue
            posts = data.get("data", {}).get("children", [])
            for p in posts[:10]:
                post = p.get("data", {})
                title  = post.get("title","")
                purl   = f"https://reddit.com{post.get('permalink','')}"
                selftext = (post.get("selftext","") or "")[:300]
                score  = post.get("score", 0)
                subr   = post.get("subreddit","")
                created = post.get("created_utc", 0)
                if not title or score < 5: continue
                content   = f"{title} {selftext}"
                relevance = self._score_relevance(content)
                if relevance < 0.3: continue
                pub = datetime.fromtimestamp(created, timezone.utc).isoformat() if created else now_iso()
                items.append({
                    "type": "feed_item",
                    "title": title[:200],
                    "summary": selftext,
                    "url": purl,
                    "source": f"Reddit r/{subr}",
                    "source_type": "reddit",
                    "category": self._classify(content, "community"),
                    "entities": self._extract_entities(content),
                    "published": pub,
                    "fetched_at": now_iso(),
                    "relevance": min(relevance + (score/1000 if score<500 else 0.5), 1.0),
                })
        return items

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _score_relevance(self, text: str) -> float:
        tl = text.lower()
        score = 0.0
        for kw in THREAT_KEYWORDS["critical"]:
            if kw in tl: score += 0.25
        for kw in THREAT_KEYWORDS["high"]:
            if kw in tl: score += 0.12
        for kw in THREAT_KEYWORDS["medium"]:
            if kw in tl: score += 0.06
        return min(score, 1.0)

    def _extract_entities(self, text: str) -> List[str]:
        """Extract threat actor names, CVEs, malware names from text."""
        entities = []
        tl = text.lower()
        # CVEs
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
        entities.extend([c.upper() for c in cves])
        # Known threat actors / malware
        known = ["lockbit","blackcat","alphv","clop","cl0p","rhysida","akira",
                 "play","medusa","hunters","qilin","dragonforce","ransomhub",
                 "lazarus","apt28","apt29","volt typhoon","salt typhoon",
                 "emotet","qakbot","icedid","cobalt strike","mimikatz",
                 "redline","stealc","formbook","asyncrat","njrat","darkgate",
                 "scattered spider","lapsus$","fin7","ta505"]
        for k in known:
            if k in tl and k.title() not in entities:
                entities.append(k.title())
        return list(dict.fromkeys(entities))[:10]  # Deduplicate, max 10

    def _classify(self, text: str, default: str) -> str:
        tl = text.lower()
        if any(k in tl for k in ["ransomware","ransom","lockbit","victim","leak"]): return "ransomware"
        if any(k in tl for k in ["apt","nation","state","espionage","spy"]): return "apt"
        if any(k in tl for k in ["malware","trojan","rat","stealer","botnet"]): return "malware"
        if any(k in tl for k in ["cve-","vulnerability","exploit","patch","zero-day"]): return "vulnerability"
        if any(k in tl for k in ["phishing","credential","password","breach","leak"]): return "credential"
        return default

    def _parse_date(self, date_str: str) -> str:
        if not date_str: return now_iso()
        try:
            from dateutil import parser
            return parser.parse(date_str).isoformat()
        except Exception:
            return now_iso()

    @staticmethod
    def _xml_text(element, tags: list, ns: dict = None) -> str:
        for tag in tags:
            try:
                if ns and ":" in tag:
                    child = element.find(tag, ns)
                else:
                    child = element.find(tag)
                if child is not None and child.text:
                    return child.text.strip()
            except Exception:
                pass
        return ""
