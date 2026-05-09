"""
connectors/hibp.py — HaveIBeenPwned connector (Tier 2, API key required).
Tracks data breaches and ransomware disclosures.
Enabled only when ENABLE_HIBP=true and HIBP_API_KEY is set.
"""

from typing import Any, Dict, List
from connectors.base import BaseConnector, now_iso
from config import settings


class HIBPConnector(BaseConnector):
    name = "hibp"
    display_name = "HaveIBeenPwned"
    tier = 2

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "hibp-api-key": settings.HIBP_API_KEY,
            "User-Agent": "CyberXTron-TIP/1.0",
        }

    async def fetch(self) -> List[Dict[str, Any]]:
        if not settings.ENABLE_HIBP:
            self.logger.debug("HIBP disabled")
            return []
        if not settings.HIBP_API_KEY:
            self.logger.warning("HIBP API key not set")
            return []

        records = []
        records.extend(await self._fetch_latest_breaches())
        return records

    async def _fetch_latest_breaches(self) -> List[Dict[str, Any]]:
        """Fetch the most recent data breaches from HIBP."""
        data = await self._get(
            f"{self.BASE_URL}/breaches",
            headers=self.headers,
        )
        if not isinstance(data, list):
            return []

        # Sort by AddedDate descending, take last 30
        sorted_breaches = sorted(
            data,
            key=lambda x: x.get("AddedDate", ""),
            reverse=True,
        )[:30]

        records = []
        for breach in sorted_breaches:
            name = breach.get("Name", "").strip()
            domain = breach.get("Domain", "").strip()
            added_date = breach.get("AddedDate", now_iso())
            breach_date = breach.get("BreachDate", "")
            description = breach.get("Description", "")
            data_classes = breach.get("DataClasses", [])
            is_verified = breach.get("IsVerified", False)
            pw_count = breach.get("PwnCount", 0)

            confidence = "high" if is_verified else "medium"
            tags = ["breach", "hibp"]
            if "Passwords" in data_classes:
                tags.append("credentials")

            # If breach has a domain, create a domain IOC
            if domain:
                records.append(
                    self.make_ioc(
                        source=self.name,
                        ioc=domain,
                        ioc_type="domain",
                        tags=tags,
                        confidence=confidence,
                        first_seen=breach_date or added_date,
                        last_seen=added_date,
                        description=(
                            f"HIBP breach: {name} | "
                            f"Records: {pw_count:,} | "
                            f"Data: {', '.join(data_classes[:5])}"
                        ),
                        raw=breach,
                    )
                )

            # Emit threat record for the breach
            records.append({
                "source": self.name,
                "type": "threat",
                "threat_actor": "unknown",
                "title": f"Data Breach: {name}",
                "description": f"{description[:300]} | Affected records: {pw_count:,}",
                "malware": "",
                "targeted_industries": [],
                "targeted_countries": [],
                "techniques": [],
                "confidence": confidence,
                "first_seen": breach_date or added_date,
                "last_seen": added_date,
                "raw": breach,
            })

        return records
