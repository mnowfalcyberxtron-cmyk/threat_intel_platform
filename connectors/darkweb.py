"""
connectors/darkweb.py — Dark Web Monitoring via Tor SOCKS5 proxy.
Monitors real active ransomware leak sites (.onion).
Requires: tor running on localhost:9050

Install Tor:
  Linux: sudo apt install tor && sudo systemctl start tor
  Mac:   brew install tor && brew services start tor
  Windows: Install Tor Browser (port 9150)

Verify Tor works:
  curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
"""

import re
import asyncio
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, now_iso
from config import settings

try:
    from aiohttp_socks import ProxyConnector
    import aiohttp
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from database.db import Database

class DarkWebConnector(BaseConnector):
    name = "darkweb"
    display_name = "Dark Web Monitor (Tor)"
    tier = 1
    
    def __init__(self, db: Optional[Database] = None):
        super().__init__()
        self.db = db

    async def fetch(self) -> List[Dict[str, Any]]:
        if not settings.ENABLE_DARKWEB:
            self.logger.debug("Dark web monitoring disabled — set ENABLE_DARKWEB=true in .env")
            return []
        if not HAS_SOCKS:
            self.logger.error("aiohttp-socks not installed: pip install aiohttp-socks")
            return []
        if not HAS_BS4:
            self.logger.error("beautifulsoup4 not installed: pip install beautifulsoup4")
            return []

        # Verify Tor connectivity first
        if not await self._verify_tor():
            self.logger.error("Tor not reachable at %s:%d — is Tor running?",
                settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT)
            return []

        # Get sites to monitor: from DB if available, else fallback to config
        monitored_sites = []
        if self.db:
            db_sites = await self.db.get_all_onion_sites(active_only=True)
            for s in db_sites:
                monitored_sites.append({"group": s["group_name"], "url": s["url"]})
        
        # Merge with config sites (ensuring uniqueness)
        config_urls = {s["url"] for s in monitored_sites}
        for s in settings.ONION_SITES:
            if s["url"] not in config_urls:
                monitored_sites.append(s)

        if not monitored_sites:
            self.logger.info("No .onion sites to monitor.")
            return []

        results = []
        for site in monitored_sites:
            try:
                self.logger.info("Probing: %s (%s)", site["group"], site["url"][:50])
                html = await self._fetch_onion(site["url"])
                if html:
                    victims = self._parse_site(html, site["group"], site["url"])
                    results.extend(victims)
                    self.logger.info("Dark web [%s]: %d victims found", site["group"], len(victims))
                else:
                    self.logger.debug("No response from %s", site["group"])
            except Exception as e:
                self.logger.debug("Failed %s: %s", site["group"], e)
            # Brief pause between .onion requests
            await asyncio.sleep(2)

        self.logger.info("Dark web total: %d victim records", len(results))
        return results

    async def _verify_tor(self) -> bool:
        """Quick connectivity check via Tor SOCKS5."""
        try:
            proxy = f"socks5://{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}"
            connector = ProxyConnector.from_url(proxy)
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
                async with sess.get("https://check.torproject.org/api/ip") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("IsTor"):
                            self.logger.info("Tor verified: %s", data.get("IP","?"))
                            return True
        except Exception as e:
            self.logger.error("Tor check failed at %s:%d: %s", settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT, e)
            
        return False

    async def _fetch_onion(self, url: str) -> Optional[str]:
        proxy = f"socks5://{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}"
        try:
            connector = ProxyConnector.from_url(proxy)
            timeout = aiohttp.ClientTimeout(total=45)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.5",
            }
            
            full_url = url if url.startswith("http") else f"http://{url}"
                
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
                async with sess.get(full_url, headers=headers, allow_redirects=True) as resp:
                    if resp.status == 200:
                        raw_bytes = await resp.read()
                        return raw_bytes.decode('utf-8', errors='replace')
                    self.logger.debug("HTTP %d from %s", resp.status, full_url[:50])
        except asyncio.TimeoutError:
            self.logger.debug("Timeout: %s", url[:50])
        except Exception as e:
            self.logger.debug("Fetch error %s: %s", url[:50], e)
        return None

    def _parse_site(self, html: str, group_name: str, onion_url: str = "") -> List[Dict]:
        """Generic leak site parser — extracts victim postings."""
        if not html or len(html) < 200:
            return []
        soup = BeautifulSoup(html, "html.parser")
        victims = []
        seen = set()

        # Strategy 1: Look for structured victim cards
        card_selectors = [
            {"class": re.compile(r"victim|company|target|post|card|item|leak|entry", re.I)},
            {"class": re.compile(r"col-|row|list-item|article", re.I)},
        ]

        found_elements = []
        for sel in card_selectors:
            elements = soup.find_all(["div","article","li","section"], sel)
            if len(elements) >= 2:
                found_elements = elements
                break

        # Strategy 2: Look for heading tags as victim names
        if not found_elements:
            found_elements = soup.find_all(["h1","h2","h3","h4"])

        for el in found_elements[:60]:
            name = self._extract_name(el)
            if not name or len(name) < 3 or len(name) > 150:
                continue
            # Filter out nav/menu items
            skip_words = {"home","about","contact","faq","news","blog","login","terms","privacy","dark","onion"}
            if name.lower() in skip_words: continue
            
            # Filter URL strings and emails out of darkweb extraction
            if "://" in name or ".onion" in name or "@" in name: continue
            
            key = name.lower().strip()
            if key in seen: continue
            seen.add(key)

            desc    = self._extract_desc(el)
            date_str = self._extract_date(el)
            country  = self._extract_country(el)
            industry = self._extract_industry(el)
            size_str = self._extract_size(el)

            victims.append(self.make_victim(
                source=self.name,
                group_name=group_name,
                victim_name=name,
                description=desc,
                country=country,
                industry=industry,
                leak_date=date_str,
                source_url=f"[dark web — {group_name.lower()}]",
                onion_url=onion_url,
                status="published",
                data_size=size_str,
            ))

        return victims[:50]

    def _extract_name(self, el) -> str:
        for tag in el.find_all(["h1","h2","h3","h4","strong","b","a"]):
            t = tag.get_text(" ", strip=True)
            if 3 < len(t) < 120 and not t.startswith("http"):
                return t
        t = el.get_text(" ", strip=True)
        lines = [l.strip() for l in t.split("\n") if l.strip()]
        return lines[0][:100] if lines else ""

    def _extract_desc(self, el) -> str:
        for tag in el.find_all(["p","span"], {"class": re.compile(r"desc|text|content|info|detail", re.I)}):
            t = tag.get_text(" ", strip=True)
            if len(t) > 20:
                return t[:400]
        text = el.get_text(" ", strip=True)
        return text[:300]

    def _extract_date(self, el) -> str:
        for t in el.find_all("time"):
            return t.get("datetime","") or t.get_text(strip=True)
        for tag in el.find_all(True, {"class": re.compile(r"date|time|published|added|posted", re.I)}):
            return tag.get_text(strip=True)[:30]
        # Look for date patterns in text
        text = el.get_text()
        m = re.search(r"\b(20\d{2}[-/]\d{2}[-/]\d{2}|\d{2}/\d{2}/20\d{2})\b", text)
        return m.group(0) if m else ""

    def _extract_country(self, el) -> str:
        text = el.get_text()
        countries = re.findall(
            r"\b(USA|United States|UK|United Kingdom|Germany|France|Italy|Canada|"
            r"Australia|India|Japan|Brazil|Russia|China|Spain|Netherlands|"
            r"Mexico|South Korea|Switzerland|Sweden|Norway|Denmark|Poland|"
            r"Belgium|Austria|Singapore|UAE|Saudi Arabia|Turkey|Argentina)\b",
            text, re.IGNORECASE)
        return countries[0].upper() if countries else ""

    def _extract_industry(self, el) -> str:
        text = el.get_text().lower()
        sectors = [
            ("Healthcare","hospital|clinic|medical|health|pharma|dental"),
            ("Finance","bank|financ|insurance|investment|credit|payment"),
            ("Education","university|school|college|education|academ"),
            ("Government","government|municipality|federal|ministry|agency"),
            ("Manufacturing","manufactur|factory|industrial|production"),
            ("Technology","software|tech|cyber|IT|cloud|saas"),
            ("Legal","law firm|attorney|legal|counsel|solicitor"),
            ("Retail","retail|ecommerce|store|shop|commerce"),
            ("Energy","energy|oil|gas|power|utility|electric"),
            ("Construction","construction|engineer|infrastructure|architect"),
        ]
        for name, pattern in sectors:
            if re.search(pattern, text, re.I):
                return name
        return ""

    def _extract_size(self, el) -> str:
        text = el.get_text()
        m = re.search(r"(\d+(?:\.\d+)?\s*(?:GB|MB|TB|KB))", text, re.IGNORECASE)
        return m.group(0) if m else ""
