"""
connectors/telegram_monitor.py — CyberXTron Telegram Threat Monitor
Automatically discovers, categorizes, and checks uptime for threat-related Telegram channels.
Focuses on: Infostealers, Stealer Logs, Combolists, and Database Leaks.
"""
import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import List, Dict, Any
import aiohttp
from bs4 import BeautifulSoup
from connectors.base import BaseConnector, now_iso
from database.db import Database
from config import settings

logger = logging.getLogger("connector.telegram")

class TelegramMonitorConnector(BaseConnector):
    name = "telegram_monitor"
    display_name = "Telegram Threat Monitor"
    tier = 1

    def __init__(self, db: Database = None):
        super().__init__()
        self.db = db
        # High-interest keywords for categorization
        self.categories = {
            "infostealer_logs": ["infostealer", "stealer", "redline", "vidar", "raccoon", "lumma", "meta stealer", "titan stealer", "logs", "cloud logs", "personal logs", "stealer log", "premium logs"],
            "combolist": ["combolist", "combo", "hits", "hq combo", "combonew", "user:pass", "mail:pass", "mailpass", "userpass", "sqli"],
            "database_leaks": ["database", "db leak", "leak", "breach", "sql dump", "scraped", "json dump", "csv leak", "full db", "private db"],
            "ransomware": ["ransomware", "leak site", "extortion", "affiliate", "encrypted", "decryptor", "lockbit", "clop", "alphv", "blackcat"],
            "hacktivism": ["hacktivist", "anonymous", "ddos", "deface", "operation", "cyber army", "hackers", "cyber attack"],
            "marketplace": ["market", "escrow", "black market", "sell logs", "buy logs", "shop", "account shop", "premium accounts", "selling"],
            "carding": ["carding", "cc fullz", "dumps", "bin", "cvv", "cloned card", "bank login", "paypal", "stripe"],
            "exploits": ["exploit", "0day", "poc", "vulnerability", "rce", "cve", "bypass", "fud", "rce exploit", "zero day"],
            "osint": ["osint", "threat intel", "cyber security", "malware analysis", "cti", "investigation", "forensics"]
        }

    async def fetch(self) -> List[Dict[str, Any]]:
        """
        1. Discover new channels from existing platform data (victims, news, markets).
        2. Verify liveness and gather metadata for all pending/active channels.
        3. Categorize channels based on metadata.
        """
        if not self.db:
            return []

        stats = {"new_handles": 0, "active": 0, "offline": 0, "alerts": 0}

        # 1. Discovery phase
        discovered_handles = await self._discover_handles()
        web_handles = await self._discover_from_web()
        
        all_new = discovered_handles.union(web_handles)
        for handle in all_new:
            # Clean handle: remove @ if present
            handle = handle.lstrip("@").strip()
            if not handle: continue
            
            inserted, is_new = await self.db.upsert_telegram_channel({"handle": handle, "category": "discovered"})
            if is_new:
                stats["new_handles"] += 1

        # 2. Monitoring phase
        # Get all channels that need checking (active or pending)
        async with self.db._conn.execute("SELECT id, handle, last_status FROM telegram_channels") as cur:
            channels = await cur.fetchall()

        logger.info(f"[TelegramMonitor] Checking liveness for {len(channels)} channels...")
        
        # Concurrency limit for checking t.me
        semaphore = asyncio.Semaphore(15) 
        
        async def _check_and_update(chan):
            async with semaphore:
                cid, handle, old_status = chan
                metadata = await self._check_handle_metadata(handle)
                
                if metadata["status"] == "active":
                    stats["active"] += 1
                    category = self._categorize(metadata["name"] + " " + metadata["description"])
                    await self.db.upsert_telegram_channel({
                        "handle": handle,
                        "name": metadata["name"],
                        "description": metadata["description"],
                        "subscriber_count": metadata["subscribers"],
                        "category": category
                    })
                    await self.db.update_telegram_status(cid, "200", metadata["subscribers"])
                    
                    if old_status != "200" and metadata["subscribers"] > 0:
                        stats["alerts"] += 1
                        await self.db.create_alert({
                            "alert_type": "telegram_new_active",
                            "title": f"📢 Active Telegram Channel Found: @{handle}",
                            "description": f"New active threat channel: {metadata['name']}\nCategory: {category}\nSubs: {metadata['subscribers']}\nDescription: {metadata['description'][:200]}...",
                            "severity": "medium",
                            "source": "Telegram Monitor"
                        })
                else:
                    stats["offline"] += 1
                    await self.db.update_telegram_status(cid, metadata["status"], 0)

        tasks = [_check_and_update(c) for c in channels]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.info(f"TelegramMonitor finished: {stats['new_handles']} new handles | {stats['active']} active | {stats['offline']} offline")
        
        # Return stats for the scheduler to log
        return [{"type": "telegram_stats", "new": stats["new_handles"], "active": stats["active"], "alerts": stats["alerts"]}]

    async def _discover_handles(self) -> set:
        """Extract telegram handles from victims, markets, and news feeds."""
        handles = set()
        
        # Search in ransomware victims (descriptions and URLs)
        async with self.db._conn.execute("SELECT description, source_url FROM ransomware_victims WHERE description LIKE '%t.me/%' OR source_url LIKE '%t.me/%'") as cur:
            rows = await cur.fetchall()
            for r in rows:
                handles.update(self._extract_handles(r["description"] + " " + r["source_url"]))

        # Search in breach markets
        async with self.db._conn.execute("SELECT description, url FROM breach_markets WHERE description LIKE '%t.me/%' OR url LIKE '%t.me/%'") as cur:
            rows = await cur.fetchall()
            for r in rows:
                handles.update(self._extract_handles(r["description"] + " " + r["url"]))

        # Search in news feeds
        async with self.db._conn.execute("SELECT title, summary, url FROM threat_feed WHERE summary LIKE '%t.me/%' OR title LIKE '%t.me/%' OR url LIKE '%t.me/%'") as cur:
            rows = await cur.fetchall()
            for r in rows:
                handles.update(self._extract_handles(r["title"] + " " + r["summary"] + " " + r["url"]))

        return handles

    async def _discover_from_web(self) -> set:
        """Search the web for new threat-related Telegram channels using dorks."""
        handles = set()
        # High-precision dorks
        search_queries = [
            'site:t.me "infostealer logs"',
            'site:t.me "stealer logs"',
            'site:t.me "combolist"',
            'site:t.me "redline stealer"',
            'site:t.me "raccoon stealer"',
            'site:t.me "vidar stealer"',
            'site:t.me "database leak"',
            'site:t.me "cyber threat intel"',
            'site:t.me "ransomware leak"',
            'site:t.me "botnet logs"',
            'site:t.me "hacktivist operation"',
            'site:t.me "0day exploit"',
            'site:t.me "fullz dump"',
            'site:t.me "cc shop"',
            'site:t.me "malware source code"',
            'site:t.me "breach alert"',
            'site:t.me "scraped database"',
            'site:t.me "combo hq"',
            'site:t.me "stealer faked"',
            'site:t.me "log cloud"',
            'site:t.me "bank logs"',
            'site:t.me "stealer logs"',
            'site:t.me "database leak 2024"',
            'site:t.me "private cloud logs"',
            'site:t.me "combo list txt"',
            'site:t.me "malware logs"',
            'site:t.me "redline logs"',
            'site:t.me "raccoon logs"',
            'site:t.me "lumma stealer"'
        ]
        
        async with aiohttp.ClientSession() as sess:
            # We use a rotation of public search aggregators
            # DuckDuckGo HTML is generally more lenient than Google
            for query in search_queries:
                url = f"https://duckduckgo.com/html/?q={query.replace(' ', '+')}"
                try:
                    # Basic User-Agent to avoid immediate block
                    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
                    async with sess.get(url, headers=headers, timeout=15) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            new_handles = self._extract_handles(html)
                            if new_handles:
                                logger.info(f"[TelegramMonitor] Found {len(new_handles)} potential handles from web search: '{query}'")
                                handles.update(new_handles)
                        
                        # Anti-throttling delay
                        await asyncio.sleep(2.0)
                except Exception as e:
                    logger.debug(f"Web search discovery failed for '{query}': {e}")
        
        return handles

    def _extract_handles(self, text: str) -> List[str]:
        if not text: return []
        # Match t.me/handle or telegram.me/handle
        # Handles are 5-32 chars, a-z, 0-9, and underscores.
        matches = re.findall(r"(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})", text)
        return [m.lower() for m in matches]

    async def _check_handle_metadata(self, handle: str) -> Dict:
        """Scrape t.me/s/{handle} for public preview metadata."""
        url = f"https://t.me/s/{handle}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        }
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        raw_bytes = await resp.read()
                        html = raw_bytes.decode('utf-8', errors='replace')
                        soup = BeautifulSoup(html, "html.parser")
                        
                        # Check if channel exists (t.me/s shows "If you have Telegram, you can view..." if it doesn't exist)
                        if "If you have Telegram, you can view" in html and not soup.find("div", class_="tgme_channel_info_header"):
                            return {"status": "not_found", "name": "", "description": "", "subscribers": 0}

                        name = ""
                        name_el = soup.find("div", class_="tgme_channel_info_header_title")
                        if name_el: name = name_el.get_text(strip=True)
                        
                        desc = ""
                        desc_el = soup.find("div", class_="tgme_channel_info_description")
                        if desc_el: desc = desc_el.get_text(strip=True)
                                            
                        subs = 0
                        # Strategy 1: Look in counters (desktop layout)
                        counters = soup.find("div", class_="tgme_channel_info_counters")
                        if counters:
                            for counter in counters.find_all("div", class_="tgme_channel_info_counter"):
                                text = counter.get_text(strip=True).lower()
                                if "subscribers" in text or "members" in text:
                                    val_el = counter.find("span", class_="counter_value")
                                    val_text = val_el.get_text(strip=True) if val_el else text.replace("subscribers", "").replace("members", "").strip()
                                    subs = self._parse_subscriber_text(val_text)
                                    if subs > 0: break
                        
                        # Strategy 2: Look in extra info (mobile/older layout)
                        if subs == 0:
                            extra = soup.find("div", class_="tgme_page_extra")
                            if extra:
                                extra_text = extra.get_text(strip=True).lower()
                                m = re.search(r"([\d\.\s,]+[km]?)\s+(subscribers|members)", extra_text)
                                if m:
                                    subs = self._parse_subscriber_text(m.group(1))
                        
                        return {
                            "status": "active",
                            "name": name,
                            "description": desc,
                            "subscribers": subs
                        }
                    else:
                        return {"status": "offline", "name": "", "description": "", "subscribers": 0}
        except Exception as e:
            logger.debug(f"Error checking handle @{handle}: {e}")
            return {"status": "error", "name": "", "description": str(e), "subscribers": 0}

    def _parse_subscriber_text(self, text: str) -> int:
        """Helper to parse 1.2K, 3M, 1,234 style numbers."""
        if not text: return 0
        text = text.replace(" ", "").replace(",", "").lower()
        m = re.search(r"([\d\.]+)([km]?)", text)
        if not m: return 0
        try:
            val = float(m.group(1))
            unit = m.group(2)
            if unit == "k": return int(val * 1000)
            if unit == "m": return int(val * 1000000)
            return int(val)
        except:
            return 0

    def _categorize(self, text: str) -> str:
        text = text.lower()
        for cat, keywords in self.categories.items():
            if any(kw in text for kw in keywords):
                return cat
        return "general"

    async def run(self):
        """Scheduler entry point."""
        logger.info("[TelegramMonitor] Running automated discovery and check...")
        await self.fetch()
        logger.info("[TelegramMonitor] Finished cycle.")
