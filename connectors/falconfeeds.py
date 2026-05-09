"""
connectors/falconfeeds.py — FalconFeeds.io connector (Tier 2, API key required).
Fetches threat actor profiles, IOCs, and threat intelligence reports.
Enabled only when ENABLE_FALCONFEEDS=true and FALCONFEEDS_API_KEY is set.
"""

from typing import Any, Dict, List
from connectors.base import BaseConnector, now_iso
from config import settings


class FalconFeedsConnector(BaseConnector):
    name = "falconfeeds"
    display_name = "FalconFeeds.io"
    tier = 2

    BASE_URL = "https://api.falconfeeds.io"

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {settings.FALCONFEEDS_API_KEY}",
            "Content-Type": "application/json",
        }

    async def fetch(self) -> List[Dict[str, Any]]:
        if not settings.ENABLE_FALCONFEEDS:
            self.logger.debug("FalconFeeds disabled")
            return []
        if not settings.FALCONFEEDS_API_KEY:
            self.logger.warning("FalconFeeds API key not set")
            return []

        records = []
        records.extend(await self._fetch_iocs())
        records.extend(await self._fetch_threat_actors())
        return records

    async def _fetch_iocs(self) -> List[Dict[str, Any]]:
        """Fetch recent IOCs from FalconFeeds."""
        data = await self._get(
            f"{self.BASE_URL}/v1/iocs",
            headers=self.headers,
            params={"limit": 100, "days": 1},
        )
        if not data or not isinstance(data, dict):
            return []

        records = []
        for entry in data.get("data", {}).get("iocs", []) or []:
            ioc_value = entry.get("value", "").strip()
            ioc_type = self._map_type(entry.get("type", ""))
            if not ioc_value or not ioc_type:
                continue

            records.append(
                self.make_ioc(
                    source=self.name,
                    ioc=ioc_value,
                    ioc_type=ioc_type,
                    threat_actor=entry.get("threat_actor", "unknown"),
                    malware=entry.get("malware_family", ""),
                    tags=entry.get("tags", []),
                    confidence="high",
                    first_seen=entry.get("first_seen", now_iso()),
                    last_seen=entry.get("last_seen", now_iso()),
                    description=entry.get("description", "FalconFeeds IOC"),
                    raw=entry,
                )
            )
        return records

    async def _fetch_threat_actors(self) -> List[Dict[str, Any]]:
        """Fetch recent threat actor activity from FalconFeeds."""
        data = await self._get(
            f"{self.BASE_URL}/v1/threat-actors/recent",
            headers=self.headers,
        )
        if not data or not isinstance(data, dict):
            return []

        records = []
        for actor in data.get("data", []) or []:
            actor_name = actor.get("name", "").strip()
            if not actor_name:
                continue

            # Emit a threat record (not IOC)
            records.append({
                "source": self.name,
                "type": "threat",
                "threat_actor": actor_name,
                "description": actor.get("description", ""),
                "malware": ", ".join(actor.get("malware", [])),
                "targeted_countries": actor.get("target_countries", []),
                "targeted_industries": actor.get("target_industries", []),
                "techniques": actor.get("ttps", []),
                "confidence": "high",
                "first_seen": actor.get("first_seen", now_iso()),
                "last_seen": actor.get("last_seen", now_iso()),
                "raw": actor,
            })
        return records

    @staticmethod
    def _map_type(raw_type: str) -> str:
        mapping = {
            "ip": "ip",
            "ipv4": "ip",
            "ipv6": "ip",
            "domain": "domain",
            "fqdn": "domain",
            "url": "url",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "email": "email",
            "cve": "cve",
        }
        return mapping.get(raw_type.lower(), raw_type.lower())
