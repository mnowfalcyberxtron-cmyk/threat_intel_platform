"""
connectors/ransomware_live.py — Ransomware.live with short timeout + all fallbacks.

The API times out frequently. Strategy:
- Use 15s timeout (not 30s) to fail fast
- Try multiple endpoints in order
- Fall back to RansomWatch GitHub mirror (always works)
- Pro API key enables /v2/ endpoints
"""
import asyncio
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, now_iso
from config import settings

# RansomWatch is a public GitHub-hosted mirror of ransomware posts — always available
RANSOMWATCH_POSTS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
RANSOMWATCH_GROUPS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"


class RansomwareLiveConnector(BaseConnector):
    name = "ransomware_live"
    display_name = "Ransomware.live"
    tier = 1

    PUBLIC_BASE = "https://api.ransomware.live"
    TIMEOUT     = 15  # short timeout — fail fast, fall back to RansomWatch

    @property
    def _has_key(self):
        return bool(settings.ENABLE_RANSOMWARE_API and settings.RANSOMWARE_LIVE_API_KEY)

    @property
    def _headers(self):
        h = {"Accept": "application/json", "User-Agent": "CyberXTron-TIP/2.2"}
        if self._has_key:
            h["Authorization"] = f"Bearer {settings.RANSOMWARE_LIVE_API_KEY}"
            h["X-Api-Key"]     = settings.RANSOMWARE_LIVE_API_KEY
        return h

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []
        stats = {"victims": 0, "groups": 0, "scraped": 0}

        # Strategy 1: Try Ransomware.live API with short timeout
        rl_victims = await self._try_rl_api()
        if rl_victims:
            records.extend(rl_victims)
            stats["victims"] += len(rl_victims)
            self.logger.info("Ransomware.live API: %d victims", len(rl_victims))
        
        # Strategy 2: Fetch full FQDN/Onion list from Ransomware.live groups
        rl_groups = await self._try_rl_groups()
        if rl_groups:
            records.extend(rl_groups)
            stats["groups"] += len(rl_groups)
            self.logger.info("Ransomware.live API: %d groups/onions", len(rl_groups))

        if not rl_victims and not rl_groups:
            # Strategy 3: Fall back to RansomWatch GitHub mirror (always works)
            self.logger.info("Ransomware.live API unavailable — using RansomWatch mirror")
            rw_records = await self._fetch_ransomwatch()
            records.extend(rw_records)
            # Count victims in rw_records
            stats["victims"] += len([r for r in rw_records if r.get("type") == "victim"])
            stats["groups"] += len([r for r in rw_records if r.get("type") == "ioc"])

        # Strategy 4: Deep Scrape for recently active groups
        active_groups = set()
        for v in (rl_victims or []):
            if v.get("group_name") and v["group_name"] != "unknown":
                active_groups.add(v["group_name"])
                
        # To avoid being blocked, only scrape a few groups per fetch
        # Prioritize groups that are very active
        for g in list(active_groups)[:8]: # Increased to 8
            self.logger.info("Scraping deep IOCs for active group: %s", g)
            scraped_iocs = await self.scrape_group_iocs(g)
            if scraped_iocs:
                records.extend(scraped_iocs)
                stats["scraped"] += len(scraped_iocs)

        self.logger.info("Ransomware.live total: %d records (%d victims, %d groups, %d scraped iocs)", 
                         len(records), stats["victims"], stats["groups"], stats["scraped"])
        
        # We append a telemetry record that the scheduler can use
        records.append({
            "type": "telemetry",
            "source": self.name,
            "victims_new": stats["victims"],
            "groups_new": stats["groups"],
            "scraped_new": stats["scraped"]
        })
        return records

    async def _try_rl_groups(self) -> List[Dict[str, Any]]:
        """Fetch all groups and their .onion URLs from Ransomware.live/groups."""
        import aiohttp
        url = f"{self.PUBLIC_BASE}/groups"
        try:
            timeout = aiohttp.ClientTimeout(total=self.TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(url, headers=self._headers) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        groups = self._extract_list(data)
                        if groups:
                            return self._parse_groups(groups)
        except Exception as e:
            self.logger.debug("RL Groups error: %s", e)
        return []

    async def _try_rl_api(self) -> List[Dict[str, Any]]:
        """Try Ransomware.live API endpoints with 15s timeout."""
        import aiohttp
        import ssl

        # Build ssl context
        try:
            import certifi
            ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ssl_ctx = False

        endpoints = []
        if self._has_key:
            endpoints = [
                f"{self.PUBLIC_BASE}/v2/recentvictims",
                f"{self.PUBLIC_BASE}/v2/victims",
            ]
        else:
            endpoints = [
                f"{self.PUBLIC_BASE}/recentvictims",
                f"{self.PUBLIC_BASE}/victims",
            ]

        for url in endpoints:
            print(f"DEBUG RL: Fetching {url}")
            try:
                timeout = aiohttp.ClientTimeout(total=self.TIMEOUT)
                conn = aiohttp.TCPConnector(ssl=ssl_ctx)
                async with aiohttp.ClientSession(timeout=timeout, connector=conn) as sess:
                    async with sess.get(url, headers=self._headers) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            victims = self._extract_list(data)
                            if victims:
                                return self._parse_victims(victims[:1000])
            except asyncio.TimeoutError:
                self.logger.debug("RL timeout: %s", url)
            except Exception as e:
                self.logger.debug("RL error %s: %s", url, e)
        return []

    async def _fetch_ransomwatch(self) -> List[Dict[str, Any]]:
        """Fetch from RansomWatch GitHub mirror — very reliable."""
        records = []

        # Posts (victims)
        posts_raw = await self._get(RANSOMWATCH_POSTS_URL,
            headers={"User-Agent": "CyberXTron-TIP/2.2"})
        posts = self._extract_list(posts_raw) if posts_raw else []
        if posts:
            records.extend(self._parse_victims(posts[:1000]))
            self.logger.info("RansomWatch posts: %d victims", len(records))

        # Groups (for onion IOCs)
        groups_raw = await self._get(RANSOMWATCH_GROUPS_URL,
            headers={"User-Agent": "CyberXTron-TIP/2.2"})
        groups = self._extract_list(groups_raw) if groups_raw else []
        if groups:
            records.extend(self._parse_groups(groups))

        return records

    def _parse_victims(self, victims):
        out = []
        for v in victims:
            if not isinstance(v, dict): continue
            group = (v.get("group_name") or v.get("group") or
                     v.get("gang_name") or v.get("threat_actor") or "unknown").strip()
            victim = (v.get("post_title") or v.get("victim") or
                      v.get("company") or v.get("name") or "").strip()
            if not victim: continue
            
            post_url = (v.get("post_url") or v.get("url") or "").strip()
            p_onion = post_url if ".onion" in post_url else ""
            p_source = post_url if ".onion" not in post_url else ""
            
            # --- SPECIAL HANDLING FOR QILIN ---
            is_qilin = "qilin" in group.lower() or "qilin" in victim.lower()
            if is_qilin:
                group = "✨ QILIN (Aggressive)"
                self.logger.info(f"Ransomware.live: Detected Qilin activity for victim {victim}")

            print(f"DEBUG RL: type(v)={type(v)} keys={list(v.keys()) if isinstance(v,dict) else 'N/A'}")
            leak_val = v.get("published") or v.get("leak_date") or v.get("date") or ""
            print(f"DEBUG RL: victim={victim} published={v.get('published')} final={leak_val}")
            
            out.append(self.make_victim(
                source=self.name,
                group_name=group,
                victim_name=victim,
                description=(v.get("description") or v.get("body") or "")[:400],
                country=(v.get("country") or "").upper(),
                industry=(v.get("activity") or v.get("sector") or v.get("industry") or ""),
                website=(v.get("website") or v.get("domain") or ""),
                leak_date=str(leak_val),
                source_url=p_source,
                onion_url=p_onion,
                data_size=str(v.get("size") or v.get("data_size") or ""),
            ))
        return out

    def _parse_groups(self, groups):
        records = []
        for g in groups:
            if not isinstance(g, dict): continue
            name = (g.get("name") or "").strip()
            if not name: continue
            for loc in (g.get("locations") or []):
                url = ""
                if isinstance(loc, dict):
                    url = loc.get("fqdn") or loc.get("url") or ""
                elif isinstance(loc, str):
                    url = loc
                if url and ".onion" in url:
                    records.append(self.make_ioc(
                        source=self.name, ioc=url.strip(), ioc_type="domain",
                        threat_actor=name, malware="ransomware",
                        tags=["ransomware","leak_site","onion"],
                        confidence="high",
                        description=f"Ransomware group {name} leak site",
                    ))
        return records

    async def get_group_profile(self, group_name):
        if not self._has_key: return None
        import aiohttp
        try:
            timeout = aiohttp.ClientTimeout(total=self.TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(
                    f"{self.PUBLIC_BASE}/v2/group/{group_name}",
                    headers=self._headers
                ) as resp:
                    if resp.status == 200:
                        return await resp.json(content_type=None)
        except Exception as e:
            self.logger.debug("Group profile %s: %s", group_name, e)
        return None

    async def scrape_group_iocs(self, group_name: str) -> List[Dict[str, Any]]:
        """Scrape extended IOCs (MD5, SHA256, IPs) directly from the ransomware.live HTML page."""
        import aiohttp
        from bs4 import BeautifulSoup
        import re

        records = []
        # sanitize group name for URL
        url_group = group_name.lower().replace(" ", "").replace("✨", "").strip()
        url = f"https://www.ransomware.live/group/{url_group}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        raw_bytes = await resp.read()
                        html = raw_bytes.decode('utf-8', errors='replace')
                        soup = BeautifulSoup(html, "html.parser")
                        
                        # Strategy A: Look for "Indicators of Compromise" heading
                        heading = soup.find(string=re.compile("Indicators of Compromise", re.IGNORECASE))
                        
                        # Strategy B: Look for any <code> blocks if heading not found
                        blocks_to_check = []
                        if heading:
                            parent = heading.find_parent(["h5", "h4", "h3", "div"])
                            if parent:
                                blocks_to_check = parent.find_all_next("code")
                        
                        if not blocks_to_check:
                            # Fallback: check all code blocks on page if they look like IOCs
                            blocks_to_check = soup.find_all("code")

                        i = 0
                        while i < len(blocks_to_check):
                            val = blocks_to_check[i].get_text(strip=True)
                            
                            # If it's a type label, the next one is the value
                            if val.lower() in ["md5", "sha256", "sha1", "ip", "domain", "url", "email"]:
                                if i + 1 < len(blocks_to_check):
                                    ioc_type_str = val.lower()
                                    ioc_value = blocks_to_check[i+1].get_text(strip=True)
                                    
                                    mapped_type = ioc_type_str
                                    if "ip" in mapped_type: mapped_type = "ip"
                                    
                                    if ioc_value and len(ioc_value) > 3:
                                        records.append(self.make_ioc(
                                            source=self.name,
                                            ioc=ioc_value,
                                            ioc_type=mapped_type,
                                            threat_actor=group_name,
                                            malware="ransomware",
                                            tags=["ransomware", "scraped"],
                                            confidence="medium",
                                            description=f"Scraped IOC for {group_name}"
                                        ))
                                    i += 2
                                    continue
                            
                            # Else, try to guess type from value
                            guess_type = None
                            if re.match(r"^[a-fA-F0-9]{64}$", val): guess_type = "sha256"
                            elif re.match(r"^[a-fA-F0-9]{32}$", val): guess_type = "md5"
                            elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val): guess_type = "ip"
                            elif ".onion" in val: guess_type = "domain"
                            
                            if guess_type:
                                records.append(self.make_ioc(
                                    source=self.name,
                                    ioc=val,
                                    ioc_type=guess_type,
                                    threat_actor=group_name,
                                    malware="ransomware",
                                    tags=["ransomware", "scraped"],
                                    confidence="medium",
                                    description=f"Scraped IOC for {group_name} (auto-detected)"
                                ))
                            i += 1
        except Exception as e:
            self.logger.debug("Failed to scrape IOCs for %s: %s", group_name, e)
        return records

    async def get_all_posts(self, limit=500):
        raw = await self._get(RANSOMWATCH_POSTS_URL,
            headers={"User-Agent": "CyberXTron-TIP/2.2"})
        return self._extract_list(raw)[:limit] if raw else []

    async def search_victims(self, query):
        posts = await self.get_all_posts(limit=2000)
        q = query.lower()
        return [p for p in posts if q in (p.get("post_title") or "").lower()
                or q in (p.get("description") or "").lower()
                or q in (p.get("website") or "").lower()]

    @staticmethod
    def _extract_list(data):
        if isinstance(data, list): return data
        if isinstance(data, dict):
            for k in ("data","victims","posts","groups","results","attacks"):
                v = data.get(k)
                if isinstance(v, list): return v
        return []
