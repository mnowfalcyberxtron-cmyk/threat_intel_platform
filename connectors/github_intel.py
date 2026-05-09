"""
connectors/github_intel.py — GitHub Threat Intelligence Connector.
Monitors public repositories for malware samples, exploit PoCs,
IOC lists, and threat actor toolkits.

Uses GitHub's public search API (no key needed, rate-limited).
With a Personal Access Token: rate limit increases 10x.
"""

import re
from typing import Any, Dict, List
from connectors.base import BaseConnector, now_iso

# High-value GitHub search queries for threat intelligence
SEARCH_QUERIES = [
    # IOC feeds published as repos
    {"q": "filename:iocs.txt malware",          "label": "ioc_feed"},
    {"q": "ransomware ioc indicators 2024",     "label": "ransomware_ioc"},
    {"q": "cobalt strike c2 beacon config",     "label": "c2_beacon"},
    # PoC exploits (monitor for weaponization signals)
    {"q": "CVE-2024 proof-of-concept exploit",  "label": "cve_poc"},
    {"q": "CVE-2025 RCE exploit poc",           "label": "cve_poc_2025"},
    # Threat actor toolkits published by researchers
    {"q": "apt malware tool analysis",          "label": "apt_tool"},
    {"q": "stealer malware source code",        "label": "stealer"},
]

# Extract IOC-like patterns from README / description text
IP_PATTERN     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|ru|cn|top|xyz)\b", re.I)
CVE_PATTERN    = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_PATTERN    = re.compile(r"\b[a-fA-F0-9]{32}\b")


class GitHubIntelConnector(BaseConnector):
    name = "github_intel"
    display_name = "GitHub Threat Intel"
    tier = 1

    SEARCH_URL = "https://api.github.com/search/repositories"
    CODE_SEARCH_URL = "https://api.github.com/search/code"

    def __init__(self, github_token: str = ""):
        super().__init__()
        self._token = github_token

    @property
    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CyberXTron-TIP/1.0",
        }
        if self._token:
            headers["Authorization"] = f"token {self._token}"
        return headers

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []

        for query_config in SEARCH_QUERIES[:4]:  # Limit to avoid rate limits
            try:
                repos = await self._search_repos(query_config["q"], query_config["label"])
                records.extend(repos)
                self.logger.info(
                    "GitHub '%s': %d records", query_config["label"], len(repos)
                )
            except Exception as e:
                self.logger.warning("GitHub query failed: %s — %s", query_config["q"], e)

        return records

    async def _search_repos(self, query: str, label: str) -> List[Dict[str, Any]]:
        data = await self._get(
            self.SEARCH_URL,
            headers=self._headers,
            params={
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": 10,
            },
        )
        if not data or not isinstance(data, dict):
            return []

        records = []
        for repo in data.get("items", []):
            name = repo.get("full_name", "")
            description = repo.get("description", "") or ""
            html_url = repo.get("html_url", "")
            updated_at = repo.get("updated_at", now_iso())
            topics = repo.get("topics", [])
            stars = repo.get("stargazers_count", 0)

            if not name:
                continue

            # Extract CVEs from repo name/description
            content = f"{name} {description} {' '.join(topics)}"
            cves_found = list(set(CVE_PATTERN.findall(content)))

            for cve in cves_found:
                # Only emit CVEs from repos with some credibility (stars or known labels)
                confidence = "medium" if stars > 5 else "low"
                records.append(
                    self.make_ioc(
                        source=self.name,
                        ioc=cve.upper(),
                        ioc_type="cve",
                        tags=[label, "github", "poc"] + topics[:3],
                        confidence=confidence,
                        first_seen=updated_at,
                        last_seen=updated_at,
                        description=(
                            f"GitHub PoC/tool: {name} | "
                            f"Stars: {stars} | {description[:100]}"
                        ),
                        raw={"repo": name, "url": html_url, "stars": stars},
                    )
                )

            # Extract IPs/domains from description (threat actor infra sometimes documented)
            for ip in set(IP_PATTERN.findall(description)):
                parts = ip.split(".")
                if len(parts) == 4 and not ip.startswith(("192.168.", "10.", "127.", "0.")):
                    try:
                        if all(0 < int(p) <= 255 for p in parts):
                            records.append(
                                self.make_ioc(
                                    source=self.name,
                                    ioc=ip,
                                    ioc_type="ip",
                                    tags=[label, "github"],
                                    confidence="low",
                                    first_seen=updated_at,
                                    last_seen=updated_at,
                                    description=f"IP from GitHub repo: {name}",
                                )
                            )
                    except ValueError:
                        pass

        return records
