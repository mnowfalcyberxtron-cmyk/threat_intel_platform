"""
connectors/haveibeenransom.py — RansomWatch + breach monitoring.
Fetches from multiple GitHub mirrors since the primary can be slow.
Also fetches group .onion URLs to store alongside victims.
"""
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, now_iso

# Multiple mirror URLs for resilience
RANSOMWATCH_MIRRORS = [
    "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
    "https://raw.githubusercontent.com/joshhighet/ransomwatch/refs/heads/main/posts.json",
]
RANSOMWATCH_GROUPS = [
    "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json",
    "https://raw.githubusercontent.com/joshhighet/ransomwatch/refs/heads/main/groups.json",
]

# Alternate public sources for ransomware victim data
RANSOMDB_URL   = "https://raw.githubusercontent.com/AmazingAng/ransomware-recovery-report/main/index.json"
RANSOMWATCH_API = "https://api.ransomwatch.telemetry.ltd/posts"


class HaveIBeenRansomConnector(BaseConnector):
    """
    Fetches ransomware victim data and group .onion URLs.
    100% independent — no dependency on ransomware.live.
    """
    name = "haveibeenransom"
    display_name = "RansomWatch (GitHub Mirror)"
    tier = 1

    _GROUP_ONIONS: Dict[str, List[str]] = {}  # cache: group_name -> [onion_url, ...]

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []
        headers = {
            "User-Agent": "CyberXTron-TIP/2.3",
            "Accept":     "application/json",
            "Cache-Control": "no-cache",
        }

        # 1. Fetch groups first to build onion URL map
        await self._load_groups(headers)

        # 2. Fetch posts (victims) from mirrors
        posts = await self._fetch_posts(headers)
        if posts:
            records.extend(self._parse_posts(posts))
            self.logger.info("RansomWatch: %d victims parsed", len(records))
        else:
            self.logger.warning("RansomWatch: all mirrors returned no data")

        # 3. Emit onion domains as IOCs
        for group_name, onions in self._GROUP_ONIONS.items():
            for onion in onions:
                records.append(self.make_ioc(
                    source=self.name,
                    ioc=onion.strip().rstrip("/"),
                    ioc_type="domain",
                    threat_actor=group_name,
                    malware="ransomware",
                    tags=["ransomware","onion","leak_site",
                          group_name.lower().replace(" ","_")],
                    confidence="high",
                    description=f"RansomWatch: {group_name} leak site .onion",
                ))

        self.logger.info("RansomWatch total: %d records", len(records))
        return records

    async def _fetch_posts(self, headers: dict) -> list:
        """Try all mirrors in order."""
        for url in RANSOMWATCH_MIRRORS:
            data = await self._get(url, headers=headers)
            if isinstance(data, list) and len(data) > 0:
                self.logger.info("RansomWatch posts from: %s (%d items)", url, len(data))
                return data
            elif isinstance(data, str) and data.strip().startswith("["):
                import json
                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, list) and len(parsed) > 0:
                        return parsed
                except Exception:
                    pass

        # Try the API endpoint
        data = await self._get(RANSOMWATCH_API, headers=headers)
        if isinstance(data, list) and len(data) > 0:
            return data
        if isinstance(data, dict):
            return data.get("posts", data.get("data", []))

        return []

    async def _load_groups(self, headers: dict):
        """Load group profiles to extract .onion URLs."""
        for url in RANSOMWATCH_GROUPS:
            data = await self._get(url, headers=headers)
            groups = []
            if isinstance(data, list):
                groups = data
            elif isinstance(data, str) and data.strip().startswith("["):
                import json
                try: groups = json.loads(data)
                except: pass

            if groups:
                self.logger.info("RansomWatch groups: %d loaded", len(groups))
                for g in groups:
                    if not isinstance(g, dict): continue
                    name = (g.get("name") or "").strip()
                    if not name: continue
                    onions = []
                    for loc in (g.get("locations") or []):
                        fqdn = ""
                        if isinstance(loc, dict):
                            fqdn = loc.get("fqdn") or loc.get("url") or ""
                        elif isinstance(loc, str):
                            fqdn = loc
                        if fqdn and ".onion" in fqdn:
                            onions.append(fqdn.strip())
                    if onions:
                        self._GROUP_ONIONS[name] = onions
                        # Also store normalized versions
                        self._GROUP_ONIONS[name.lower()] = onions
                return  # success

    def _parse_posts(self, posts: list) -> List[Dict[str, Any]]:
        out = []
        seen = set()
        for p in posts:
            if not isinstance(p, dict): continue
            group  = (p.get("group_name") or "unknown").strip()
            victim = (p.get("post_title") or p.get("title") or "").strip()
            if not victim: continue
            key = f"{group.lower()}:{victim.lower()}"
            if key in seen: continue
            seen.add(key)
            published = (p.get("published") or p.get("discovered") or "")

            # Find onion URL for this group
            onion_url = self._find_onion(group)

            out.append(self.make_victim(
                source=self.name,
                group_name=group,
                victim_name=victim,
                description=(p.get("description") or "")[:400],
                country=(p.get("country") or "").upper(),
                industry=(p.get("sector") or p.get("industry") or ""),
                website=(p.get("website") or ""),
                leak_date=str(published)[:10] if published else "",
                source_url=p.get("url") or "",
                data_size="",
                onion_url=onion_url,
            ))
        return out

    def _find_onion(self, group_name: str) -> str:
        """Find .onion URL for a group name."""
        if not group_name: return ""
        # Try exact match
        onions = self._GROUP_ONIONS.get(group_name) or \
                 self._GROUP_ONIONS.get(group_name.lower())
        if onions: return onions[0]
        # Fuzzy match
        glow = group_name.lower()
        for k, v in self._GROUP_ONIONS.items():
            if k.lower() in glow or glow in k.lower():
                return v[0]
        return ""

    def get_group_onion(self, group_name: str) -> Optional[str]:
        """Public method to get onion URL for a group."""
        return self._find_onion(group_name) or ""
