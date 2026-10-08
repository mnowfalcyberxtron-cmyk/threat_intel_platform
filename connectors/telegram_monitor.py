"""
connectors/telegram_monitor.py — ThreatIntel Telegram Threat Monitor
Multi-source autonomous discovery engine focused EXCLUSIVELY on:
  - Infostealer / Stealer Logs
  - Combolists
  - ULP (URL:Login:Password / mail:pass)

Discovery Sources:
  1. DuckDuckGo web dorks (site:t.me)
  2. Bing web dorks (site:t.me)
  3. tgstat.com channel search
  4. telemetr.io channel search
  5. Cross-channel mention mining (t.me/s/ public posts of known channels)
  6. Seed handle list — well-known entry-point channels
"""
import asyncio
import logging
import random
import re
from typing import List, Dict, Any, Set

import aiohttp
from bs4 import BeautifulSoup

from connectors.base import BaseConnector, now_iso
from database.db import Database
from config import settings

logger = logging.getLogger("connector.telegram")

# ── Target categories only ─────────────────────────────────────────────────────
TARGET_CATEGORIES = {"infostealer_logs", "combolist", "ulp"}

# ── Known seed channels (used as starting points for cross-channel mining) ────
SEED_HANDLES = [
    # Infostealer / Stealer Logs
    "free_logs", "stealc_logs", "logcloud", "malwarelogs", "premiumlogs",
    "redline_logs", "raccoonlogs", "vidar_logs", "lumma_logs", "metastealer_logs",
    "stealer_logs_free", "privatelogcloud", "infostealerlogs", "stealerlogscloud",
    "free_stealer_logs", "logs_stealer", "infostealer_channel", "logschannel",
    "stealer_logs_channel", "botnet_logs", "malware_logs_free",
    # Combolist
    "free_combolist", "combolistfree", "combolists", "hqcombo", "combolistchannel",
    "combolisthq", "freecombo", "freshcombo", "combolistnew", "hq_combo",
    "combolistpublic", "fresh_combo", "combo_list_free", "combolistfresh",
    # ULP / mail:pass / url:login
    "mail_pass", "ulp_cloud", "ulpfree", "mailpasslogs", "urlloginpass",
    "mail_pass_logs", "ulp_logs", "freeulp", "ulp_free_channel", "mailpass_free",
    "loginpassfree", "user_pass_logs", "ulp_channel_free", "fresh_ulp",
]

# ── Search dorks for DuckDuckGo & Bing ────────────────────────────────────────
WEB_DORKS = [
    # Infostealer / stealer logs
    'site:t.me "stealer log channel"',
    'site:t.me "stealer logs"',
    'site:t.me "infostealer log"',
    'site:t.me "infostealer logs"',
    'site:t.me "stealer log free"',
    'site:t.me "free stealer logs"',
    'site:t.me "redline logs"',
    'site:t.me "raccoon logs"',
    'site:t.me "vidar logs"',
    'site:t.me "lumma logs"',
    'site:t.me "log cloud"',
    'site:t.me "private cloud logs"',
    'site:t.me "malware logs"',
    'site:t.me "botnet logs"',
    'site:t.me "premium logs"',
    'site:t.me "stealc logs"',
    # Combolist
    'site:t.me "combolist"',
    'site:t.me "combo list"',
    'site:t.me "free combolist"',
    'site:t.me "fresh combo"',
    'site:t.me "hq combo"',
    'site:t.me "combo list channel"',
    'site:t.me "combolists free"',
    'site:t.me "combolist txt"',
    'site:t.me "combo hits"',
    # ULP / mail:pass
    'site:t.me "ulp channel"',
    'site:t.me "ulp free"',
    'site:t.me "url:login:pass"',
    'site:t.me "mail:pass"',
    'site:t.me "user:pass"',
    'site:t.me "mailpass"',
    'site:t.me "loginpass"',
    'site:t.me "ulp logs"',
    'site:t.me "fresh ulp"',
    'site:t.me "url login password"',
    'site:t.me "mailpasslogs"',
]

# ── tgstat search queries ──────────────────────────────────────────────────────
TGSTAT_QUERIES = [
    "stealer logs", "infostealer", "combolist", "ulp logs",
    "mail pass", "stealer log channel", "free logs", "redline logs",
    "raccoon logs", "lumma stealer", "vidar logs", "log cloud",
    "combo list", "mailpass", "url login pass",
]

# ── Category keyword map ───────────────────────────────────────────────────────
CATEGORY_KEYWORDS = {
    "infostealer_logs": [
        "infostealer", "stealer", "redline", "vidar", "raccoon", "lumma",
        "stealc", "meta stealer", "titan stealer", "stealer log", "stealer logs",
        "infostealer log", "botnet logs", "malware logs", "log cloud",
        "personal logs", "premium logs", "private logs", "fresh logs",
        "free logs", "log channel", "logs channel",
    ],
    "combolist": [
        "combolist", "combo list", "combo", "hits", "hq combo", "fresh combo",
        "free combo", "combo hq", "sqli", "combolists",
    ],
    "ulp": [
        "ulp", "url:login:pass", "url:login:password", "user:pass",
        "mail:pass", "mailpass", "userpass", "login:pass", "loginpass",
        "mail pass", "url login", "fresh ulp", "free ulp",
    ],
}


class TelegramMonitorConnector(BaseConnector):
    name = "telegram_monitor"
    display_name = "Telegram Threat Monitor"
    tier = 1

    # Rotate through multiple User-Agents to avoid blocking
    _USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ]

    def __init__(self, db: Database = None):
        super().__init__()
        self.db = db
        self.categories = CATEGORY_KEYWORDS

    def _ua(self) -> str:
        return random.choice(self._USER_AGENTS)

    # ── Main entry point ───────────────────────────────────────────────────────

    async def fetch(self) -> List[Dict[str, Any]]:
        """
        Full discovery + verification cycle:
          1. Gather handles from all discovery sources in parallel
          2. Insert new handles as pending
          3. Verify liveness + categorize all channels
          4. Purge anything that doesn't match the 3 target categories
        """
        if not self.db:
            return []

        stats = {"new_handles": 0, "active": 0, "offline": 0, "alerts": 0, "purged": 0}

        logger.info("[TelegramMonitor] Starting multi-source discovery...")

        # 1. Run all discovery sources concurrently
        results = await asyncio.gather(
            self._discover_from_seeds(),
            self._discover_from_web_dorks("duckduckgo"),
            self._discover_from_web_dorks("bing"),
            self._discover_from_tgstat(),
            self._discover_from_telemetr(),
            self._discover_from_cross_channel_mentions(),
            return_exceptions=True,
        )

        all_handles: Set[str] = set()
        source_names = ["seeds", "duckduckgo", "bing", "tgstat", "telemetr", "cross-channel"]
        for name, result in zip(source_names, results):
            if isinstance(result, Exception):
                logger.warning(f"[TelegramMonitor] {name} discovery error: {result}")
            elif result:
                logger.info(f"[TelegramMonitor] {name}: found {len(result)} handles")
                all_handles.update(result)

        # 2. Insert new discovered handles
        for raw_handle in all_handles:
            handle = raw_handle.lstrip("@").strip().lower()
            if not handle or len(handle) < 5 or len(handle) > 32:
                continue
            # Skip obvious non-channels (Telegram system handles)
            if handle in {"joinchat", "share", "bot", "addstickers", "addtheme", "c"}:
                continue
            _, is_new = await self.db.upsert_telegram_channel({"handle": handle, "category": "pending_check"})
            if is_new:
                stats["new_handles"] += 1

        logger.info(f"[TelegramMonitor] Discovery done. {stats['new_handles']} new handles queued. Verifying all channels...")

        # 3. Verify liveness and categorize
        async with self.db._conn.execute("SELECT id, handle, last_status FROM telegram_channels") as cur:
            channels = await cur.fetchall()

        semaphore = asyncio.Semaphore(20)

        async def _check_and_update(chan):
            async with semaphore:
                cid, handle, old_status = chan
                metadata = await self._check_handle_metadata(handle)

                if metadata["status"] == "active":
                    category = self._categorize(metadata["name"] + " " + metadata["description"])

                    # Purge if not in target categories
                    if category not in TARGET_CATEGORIES:
                        await self.db._conn.execute("DELETE FROM telegram_channels WHERE id = ?", (cid,))
                        await self.db._conn.commit()
                        stats["purged"] += 1
                        return

                    stats["active"] += 1
                    await self.db.upsert_telegram_channel({
                        "handle": handle,
                        "name": metadata["name"],
                        "description": metadata["description"],
                        "subscriber_count": metadata["subscribers"],
                        "category": category,
                    })
                    await self.db.update_telegram_status(cid, "200", metadata["subscribers"])

                    if old_status != "200" and metadata["subscribers"] > 0:
                        stats["alerts"] += 1
                        await self.db.create_alert({
                            "alert_type": "telegram_new_active",
                            "title": f"📢 New Active Channel: @{handle} [{category}]",
                            "description": (
                                f"Channel: {metadata['name']}\n"
                                f"Category: {category}\n"
                                f"Subscribers: {metadata['subscribers']:,}\n"
                                f"Description: {metadata['description'][:300]}"
                            ),
                            "severity": "high" if metadata["subscribers"] > 5000 else "medium",
                            "source": "Telegram Monitor",
                        })
                else:
                    stats["offline"] += 1
                    await self.db.update_telegram_status(cid, metadata["status"], 0)

        tasks = [_check_and_update(c) for c in channels]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.info(
            f"[TelegramMonitor] Cycle done — "
            f"new:{stats['new_handles']} active:{stats['active']} "
            f"offline:{stats['offline']} alerts:{stats['alerts']} purged:{stats['purged']}"
        )
        return [{"type": "telegram_stats", **stats}]

    # ── Discovery Source 1: Seed handles ─────────────────────────────────────

    async def _discover_from_seeds(self) -> Set[str]:
        """Return the hardcoded seed list as starting handles."""
        return set(SEED_HANDLES)

    # ── Discovery Source 2: Web dorks (DuckDuckGo / Bing) ────────────────────

    async def _discover_from_web_dorks(self, engine: str = "duckduckgo") -> Set[str]:
        """Search engine dorks to find t.me channel links."""
        handles: Set[str] = set()
        # Pick a random subset each cycle to avoid rate limits
        queries = random.sample(WEB_DORKS, min(len(WEB_DORKS), 20))

        async with aiohttp.ClientSession() as sess:
            for query in queries:
                try:
                    if engine == "bing":
                        url = f"https://www.bing.com/search?q={query.replace(' ', '+')}&count=30"
                    else:
                        url = f"https://duckduckgo.com/html/?q={query.replace(' ', '+')}"

                    headers = {
                        "User-Agent": self._ua(),
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": "https://www.google.com/",
                    }
                    async with sess.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        if resp.status == 200:
                            html = await resp.text(errors="replace")
                            found = self._extract_handles(html)
                            handles.update(found)
                    await asyncio.sleep(random.uniform(1.0, 2.5))
                except Exception as e:
                    logger.debug(f"[TelegramMonitor] {engine} dork failed '{query}': {e}")

        return handles

    # ── Discovery Source 3: tgstat.com ───────────────────────────────────────

    async def _discover_from_tgstat(self) -> Set[str]:
        """Scrape tgstat.com search results for channels matching target keywords."""
        handles: Set[str] = set()
        queries = random.sample(TGSTAT_QUERIES, min(len(TGSTAT_QUERIES), 8))

        async with aiohttp.ClientSession() as sess:
            for q in queries:
                try:
                    url = f"https://tgstat.com/en/search?q={q.replace(' ', '+')}&peer_type=channel"
                    headers = {
                        "User-Agent": self._ua(),
                        "Accept-Language": "en-US,en;q=0.9",
                        "Referer": "https://tgstat.com/",
                    }
                    async with sess.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        if resp.status == 200:
                            html = await resp.text(errors="replace")
                            soup = BeautifulSoup(html, "html.parser")
                            # tgstat links are href="/channel/@handle" or href="https://t.me/handle"
                            for a in soup.find_all("a", href=True):
                                href = a["href"]
                                # Pattern: /channel/@handle
                                m = re.search(r"/channel/@([a-zA-Z0-9_]{5,32})", href)
                                if m:
                                    handles.add(m.group(1).lower())
                            # Also extract raw t.me links from page
                            handles.update(self._extract_handles(html))
                    await asyncio.sleep(random.uniform(1.5, 3.0))
                except Exception as e:
                    logger.debug(f"[TelegramMonitor] tgstat failed '{q}': {e}")

        return handles

    # ── Discovery Source 4: telemetr.io ──────────────────────────────────────

    async def _discover_from_telemetr(self) -> Set[str]:
        """Scrape telemetr.io for channels matching target keywords."""
        handles: Set[str] = set()
        queries = ["stealer logs", "combolist", "ulp logs", "infostealer", "mail pass"]

        async with aiohttp.ClientSession() as sess:
            for q in queries:
                try:
                    url = f"https://telemetr.io/en/channels?search={q.replace(' ', '+')}"
                    headers = {
                        "User-Agent": self._ua(),
                        "Accept-Language": "en-US,en;q=0.9",
                        "Referer": "https://telemetr.io/",
                    }
                    async with sess.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        if resp.status == 200:
                            html = await resp.text(errors="replace")
                            # telemetr.io uses t.me links in their listings
                            handles.update(self._extract_handles(html))
                            # Also look for /en/channels/@handle patterns
                            for m in re.finditer(r"/en/channels/@?([a-zA-Z0-9_]{5,32})", html):
                                handles.add(m.group(1).lower())
                    await asyncio.sleep(random.uniform(1.5, 3.0))
                except Exception as e:
                    logger.debug(f"[TelegramMonitor] telemetr failed '{q}': {e}")

        return handles

    # ── Discovery Source 5: Cross-channel mention mining ──────────────────────

    async def _discover_from_cross_channel_mentions(self) -> Set[str]:
        """
        Scrape t.me/s/{handle} (public message preview) for each known active channel.
        Extracts any @mentions or t.me links posted by members — a key way channels
        advertise related stealer-log / combolist channels.
        """
        handles: Set[str] = set()

        # Get our currently tracked active channels
        try:
            async with self.db._conn.execute(
                "SELECT handle FROM telegram_channels WHERE last_status = '200' AND category IN ('infostealer_logs','combolist','ulp') LIMIT 30"
            ) as cur:
                known_channels = [r["handle"] for r in await cur.fetchall()]
        except Exception:
            known_channels = []

        # Also mine from seed handles directly
        mine_targets = list(set(known_channels + random.sample(SEED_HANDLES, min(10, len(SEED_HANDLES)))))

        async with aiohttp.ClientSession() as sess:
            sem = asyncio.Semaphore(5)

            async def _mine(handle: str):
                async with sem:
                    try:
                        url = f"https://t.me/s/{handle}"
                        headers = {
                            "User-Agent": self._ua(),
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        }
                        async with sess.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                            if resp.status == 200:
                                html = await resp.text(errors="replace")
                                # Extract all t.me handles from post content
                                found = self._extract_handles(html)
                                # Also extract @mentions from message text
                                mentions = re.findall(r"@([a-zA-Z0-9_]{5,32})", html)
                                all_found = set(found) | {m.lower() for m in mentions}
                                return all_found
                    except Exception as e:
                        logger.debug(f"[TelegramMonitor] cross-channel mine @{handle}: {e}")
                    return set()

            results = await asyncio.gather(*[_mine(h) for h in mine_targets], return_exceptions=True)
            for r in results:
                if isinstance(r, set):
                    handles.update(r)

        return handles

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_handles(self, text: str) -> List[str]:
        if not text:
            return []
        matches = re.findall(r"(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})", text)
        return [m.lower() for m in matches]

    async def _check_handle_metadata(self, handle: str) -> Dict:
        """Scrape t.me/{handle} for public metadata."""
        url = f"https://t.me/{handle}"
        headers = {
            "User-Agent": self._ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        html = (await resp.read()).decode("utf-8", errors="replace")
                        soup = BeautifulSoup(html, "html.parser")

                        name_el = soup.find("div", class_="tgme_page_title")
                        if not name_el:
                            return {"status": "not_found", "name": "", "description": "", "subscribers": 0}

                        name = name_el.get_text(strip=True)
                        desc = ""
                        desc_el = soup.find("div", class_="tgme_page_description")
                        if desc_el:
                            desc = desc_el.get_text(strip=True)

                        subs = 0
                        extra = soup.find("div", class_="tgme_page_extra")
                        if extra:
                            m = re.search(r"([\d\.\s,]+[km]?)\s+(subscribers|members)", extra.get_text(strip=True).lower())
                            if m:
                                subs = self._parse_subscriber_text(m.group(1))

                        return {"status": "active", "name": name, "description": desc, "subscribers": subs}
                    else:
                        return {"status": "offline", "name": "", "description": "", "subscribers": 0}
        except Exception as e:
            logger.debug(f"[TelegramMonitor] metadata check @{handle}: {e}")
            return {"status": "error", "name": "", "description": str(e), "subscribers": 0}

    def _parse_subscriber_text(self, text: str) -> int:
        if not text:
            return 0
        text = text.replace(" ", "").replace(",", "").lower()
        m = re.search(r"([\d\.]+)([km]?)", text)
        if not m:
            return 0
        try:
            val = float(m.group(1))
            unit = m.group(2)
            if unit == "k":
                return int(val * 1000)
            if unit == "m":
                return int(val * 1_000_000)
            return int(val)
        except Exception:
            return 0

    def _categorize(self, text: str) -> str:
        text = text.lower()
        for cat, keywords in self.categories.items():
            if any(kw in text for kw in keywords):
                return cat
        return "general"

    async def run(self):
        """Scheduler entry point."""
        logger.info("[TelegramMonitor] Starting autonomous discovery cycle...")
        await self.fetch()
        logger.info("[TelegramMonitor] Cycle complete.")
