"""
connectors/circl_osint.py — CIRCL OSINT / Public MISP feeds connector.
Fetches from CIRCL and other open MISP community feeds.
"""

import json
import re
from typing import Any, Dict, List
from connectors.base import BaseConnector, now_iso


class CIRCLOSINTConnector(BaseConnector):
    name = "circl_osint"
    display_name = "CIRCL OSINT Feeds"
    tier = 1

    # CIRCL public MISP feed manifests
    FEEDS = [
        {
            "name": "CIRCL OSINT",
            "manifest_url": "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
            "base_url": "https://www.circl.lu/doc/misp/feed-osint/",
        },
    ]

    # PhishTank feed (CSV) — phishing URLs
    PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"

    # CISA Known Exploited Vulnerabilities
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []

        # 1. CISA KEV — high-value CVE IOCs
        records.extend(await self._fetch_cisa_kev())

        # 2. PhishTank (limited to avoid overloading)
        records.extend(await self._fetch_phishtank())

        return records

    async def _fetch_cisa_kev(self) -> List[Dict[str, Any]]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        data = await self._get(self.CISA_KEV_URL)
        if not isinstance(data, dict):
            return []

        records = []
        vulns = data.get("vulnerabilities", [])

        # Only process the most recently added (last 50 by dateAdded)
        sorted_vulns = sorted(
            vulns,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True,
        )[:50]

        for v in sorted_vulns:
            cve_id = v.get("cveID", "").strip()
            if not cve_id:
                continue

            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            vuln_name = v.get("vulnerabilityName", "")
            short_desc = v.get("shortDescription", "")
            date_added = v.get("dateAdded", now_iso())
            due_date = v.get("dueDate", "")
            ransomware_use = v.get("knownRansomwareCampaignUse", "Unknown")

            tags = ["cve", "kev", "cisa"]
            if ransomware_use.lower() == "known":
                tags.append("ransomware")

            records.append(
                self.make_ioc(
                    source=self.name,
                    ioc=cve_id,
                    ioc_type="cve",
                    malware="",
                    tags=tags,
                    confidence="high",
                    first_seen=date_added,
                    last_seen=date_added,
                    description=(
                        f"CISA KEV: {vuln_name} | {vendor} {product} | "
                        f"Ransomware use: {ransomware_use} | Patch by: {due_date}"
                    ),
                    raw=v,
                )
            )

        return records

    async def _fetch_phishtank(self) -> List[Dict[str, Any]]:
        """Fetch PhishTank verified phishing URLs."""
        text = await self._get(self.PHISHTANK_URL)
        if not isinstance(text, str):
            return []

        records = []
        lines = text.splitlines()

        # Skip header, limit to 100 entries
        for line in lines[1:101]:
            parts = line.split(",")
            if len(parts) < 4:
                continue
            try:
                url = parts[1].strip().strip('"')
                submission_time = parts[2].strip().strip('"') if len(parts) > 2 else now_iso()
                if url.startswith("http"):
                    records.append(
                        self.make_ioc(
                            source=self.name,
                            ioc=url,
                            ioc_type="url",
                            malware="phishing",
                            tags=["phishing", "phishtank"],
                            confidence="high",
                            first_seen=submission_time,
                            last_seen=submission_time,
                            description="PhishTank verified phishing URL",
                        )
                    )
            except Exception:
                continue

        return records
