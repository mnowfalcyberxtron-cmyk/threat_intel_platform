"""
connectors/hibr.py — HaveIBeenRansom (HIBR) Pro API connector.
Fixed: tries multiple endpoints since /breaches/full returns HTTP 500.
API: https://haveibeenransom.com/api/
"""
from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, now_iso
from config import settings


class HIBRConnector(BaseConnector):
    name = "hibr"
    display_name = "HaveIBeenRansom (HIBR Pro)"
    tier = 2

    BASE_URL = "https://haveibeenransom.com"
    API_BASE  = "https://haveibeenransom.com/api"

    @property
    def _headers(self):
        return {
            "Authorization": f"Bearer {settings.HIBR_API_KEY}",
            "Accept":        "application/json",
            "User-Agent":    "ThreatIntel-TIP/2.2",
        }

    async def fetch(self) -> List[Dict[str, Any]]:
        if not settings.ENABLE_HIBR:
            return []
        if not settings.HIBR_API_KEY:
            self.logger.warning("HIBR_API_KEY not set in .env")
            return []

        self.logger.info("Fetching HIBR breach data...")

        # The /breaches/full endpoint returns HTTP 500 on some plans.
        # Try multiple endpoints in order.
        breaches = await self._try_get_breaches()
        if not breaches:
            self.logger.warning("HIBR: no breach data returned (API may be temporarily unavailable)")
            return []

        self.logger.info("HIBR: got %d breaches", len(breaches))
        return self._parse_breaches(breaches)

    async def _try_get_breaches(self) -> list:
        """Try multiple HIBR endpoints to get breach data."""
        # Endpoint 1: /breaches/full
        data = await self._get(f"{self.BASE_URL}/breaches/full", headers=self._headers)
        if isinstance(data, dict) and "breaches" in data:
            return data["breaches"]
        if isinstance(data, list):
            return data

        # Endpoint 2: /api/breaches
        data = await self._get(f"{self.API_BASE}/breaches", headers=self._headers)
        if isinstance(data, dict):
            return data.get("breaches", data.get("data", []))
        if isinstance(data, list):
            return data

        # Endpoint 3: /api/metadata/domain search (broad)
        data = await self._get(f"{self.API_BASE}/metadata/domain/all", headers=self._headers)
        if isinstance(data, dict):
            return data.get("results", [])

        return []

    def _parse_breaches(self, breaches: list) -> List[Dict[str, Any]]:
        records = []
        for b in breaches:
            if not isinstance(b, dict): continue
            group_name  = (b.get("group_name") or "unknown").strip()
            victim_name = (b.get("post_title") or "").strip()
            website     = (b.get("website") or "").strip()
            country     = (b.get("country") or "").strip().upper()
            description = (b.get("description") or "").strip()
            discovered  = str(b.get("discovered") or now_iso())
            indexed     = str(b.get("indexed") or discovered)
            post_url    = (b.get("post_url") or "")
            identities  = b.get("Identities Found", 0) or 0

            if not victim_name: continue

            records.append(self.make_victim(
                source=self.name,
                group_name=group_name,
                victim_name=victim_name,
                description=f"{description} | Identities: {identities:,}".strip(" |"),
                country=country,
                website=website,
                leak_date=indexed[:10],
                source_url=post_url,
                data_size=f"{identities:,} identities" if identities else "",
            ))

            if website and "." in website:
                records.append(self.make_ioc(
                    source=self.name,
                    ioc=website.lower().strip(),
                    ioc_type="domain",
                    threat_actor=group_name,
                    malware="ransomware",
                    tags=["hibr", "breach", "ransomware",
                          group_name.lower().replace(" ", "_")],
                    confidence="high",
                    first_seen=discovered[:19],
                    last_seen=indexed[:19],
                    description=f"HIBR: {victim_name} | {group_name} | {identities:,} identities",
                    raw=b,
                ))
        return records

    # ── Search methods (called from API routes) ──────────────────────────────

    async def search_metadata(self, field: str, query: str, page: int = 1):
        if not settings.HIBR_API_KEY: return None
        url = f"{self.API_BASE}/metadata/{field}/{query}?page={page}"
        return await self._get(url, headers=self._headers)

    async def search_fulldata(self, fields: str, query: str, search_after: int = 0, max_pages: int = 5):
        if not settings.HIBR_API_KEY: return None
        
        all_data = []
        current_search_after = search_after
        has_next = True
        page_count = 0
        first_resp = None
        
        while has_next and page_count < max_pages:
            url = f"{self.API_BASE}/fulldata/{fields}/{query}"
            if current_search_after: url += f"?search_after={current_search_after}"
            
            resp = await self._get(url, headers=self._headers)
            if not isinstance(resp, dict):
                break
                
            if first_resp is None:
                first_resp = resp
                
            data = resp.get("data", [])
            all_data.extend(data)
            
            current_search_after = resp.get("search_after")
            has_next = resp.get("has_next_page", False)
            if not current_search_after:
                has_next = False
                
            page_count += 1
            
        if first_resp is None:
            return None
            
        result = {**first_resp, "data": all_data, "has_next_page": has_next}
        if current_search_after:
            result["search_after"] = current_search_after
        return result

    async def search_fullstealer(self, fields: str, term: str, search_after: int = 0, max_pages: int = 5):
        if not settings.HIBR_API_KEY: return None
        
        all_matches = []
        current_search_after = search_after
        has_next = True
        page_count = 0
        first_resp = None
        
        while has_next and page_count < max_pages:
            url = f"{self.API_BASE}/fullstealer/{fields}/{term}"
            if current_search_after: url += f"?search_after={current_search_after}"
            
            resp = await self._get(url, headers=self._headers)
            if not isinstance(resp, dict):
                break
                
            if first_resp is None:
                first_resp = resp
                
            matches = resp.get("matches", [])
            all_matches.extend(matches)
            
            current_search_after = resp.get("search_after")
            has_next = resp.get("has_next_page", False)
            if not current_search_after:
                has_next = False
                
            page_count += 1
            
        if first_resp is None:
            return None
            
        result = {**first_resp, "matches": all_matches, "has_next_page": has_next}
        if current_search_after:
            result["search_after"] = current_search_after
        return result

    async def get_total_breaches(self):
        data = await self._get(f"{self.BASE_URL}/breaches/total", headers=self._headers)
        if isinstance(data, dict): return data.get("total")
        return None
