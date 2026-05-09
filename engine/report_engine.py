"""
engine/report_engine.py — Threat Intelligence Report Generator.
Produces structured analyst reports from stored intelligence data.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from database.db import Database

logger = logging.getLogger("engine.report")


# MITRE ATT&CK technique catalog (common ones for ransomware/APT)
MITRE_TECHNIQUES = {
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1078": "Valid Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop",
    "T1027": "Obfuscated Files or Information",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1567": "Exfiltration Over Web Service",
    "T1569": "System Services",
    "T1112": "Modify Registry",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools (AV/EDR Bypass)",
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1021.002": "SMB/Windows Admin Shares (Lateral Movement)",
}

# Tag-to-MITRE heuristics for auto-tagging
TAG_TO_TECHNIQUE = {
    "ransomware":   ["T1486", "T1490", "T1489"],
    "phishing":     ["T1566", "T1566.001", "T1566.002"],
    "c2":           ["T1071", "T1041"],
    "lateral":      ["T1021", "T1021.002"],
    "credential":   ["T1003", "T1078"],
    "exploit":      ["T1190"],
    "stealer":      ["T1041", "T1003"],
    "botnet":       ["T1071", "T1055"],
    "dropper":      ["T1059", "T1027"],
}


class ReportEngine:

    def __init__(self, db: Database):
        self.db = db

    async def generate_actor_report(
        self,
        threat_actor: str,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Generate a full threat actor intelligence report."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        # Fetch IOCs linked to this actor
        ioc_result = await self.db.get_iocs(
            page=1,
            page_size=200,
            threat_actor=threat_actor,
            date_from=cutoff,
        )
        iocs = ioc_result["items"]

        # Fetch victims linked to this actor (ransomware groups)
        victim_result = await self.db.get_victims(
            page=1,
            page_size=100,
            group_name=threat_actor,
            date_from=cutoff,
        )
        victims = victim_result["items"]

        # Extract intelligence
        ioc_summary = self._summarize_iocs(iocs)
        malware_families = self._extract_malware(iocs)
        countries = self._extract_countries(victims)
        industries = self._extract_industries(victims)
        techniques = self._infer_techniques(iocs)

        report = {
            "title": f"Threat Actor Intelligence Report: {threat_actor}",
            "summary": self._build_summary(
                threat_actor, ioc_summary, len(victims), malware_families, days
            ),
            "threat_actor": threat_actor,
            "malware": ", ".join(malware_families[:5]),
            "targeted_countries": countries,
            "targeted_industries": industries,
            "cves": self._extract_cves(iocs),
            "impact": self._build_impact(len(victims), ioc_summary, countries),
            "iocs": self._format_ioc_table(iocs[:50]),
            "techniques": [
                {"id": tid, "name": MITRE_TECHNIQUES.get(tid, tid)}
                for tid in techniques
            ],
            "ioc_counts": ioc_summary,
            "victim_count": len(victims),
            "recent_victims": [
                {
                    "name": v["victim_name"],
                    "country": v.get("country", ""),
                    "industry": v.get("industry", ""),
                    "date": v.get("discovery_date", ""),
                }
                for v in victims[:10]
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        report["raw_markdown"] = self._render_markdown(report)

        # Persist
        report_id = await self.db.save_report(report)
        report["id"] = report_id

        return report

    async def generate_summary_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate a weekly threat landscape summary."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        stats = await self.db.get_stats()

        victim_result = await self.db.get_victims(page=1, page_size=200, date_from=cutoff)
        victims = victim_result["items"]

        ioc_result = await self.db.get_iocs(
            page=1,
            page_size=200,
            confidence="high",
            date_from=cutoff,
        )
        iocs = ioc_result["items"]

        groups = {}
        for v in victims:
            g = v.get("group_name", "Unknown")
            groups[g] = groups.get(g, 0) + 1
        top_groups = sorted(groups.items(), key=lambda x: x[1], reverse=True)[:5]

        countries = self._extract_countries(victims)
        industries = self._extract_industries(victims)
        malware = self._extract_malware(iocs)

        report = {
            "title": f"Threat Intelligence Weekly Summary — Last {days} Days",
            "summary": (
                f"Over the past {days} days, the platform ingested {stats['total_iocs']} IOCs "
                f"({stats['high_confidence_iocs']} high-confidence) and tracked "
                f"{len(victims)} new ransomware victims across "
                f"{len(set(v.get('country','') for v in victims))} countries."
            ),
            "threat_actor": ", ".join(g for g, _ in top_groups),
            "malware": ", ".join(malware[:5]),
            "targeted_countries": countries,
            "targeted_industries": industries,
            "cves": self._extract_cves(iocs),
            "impact": (
                f"{len(victims)} organizations victimized by ransomware in {days} days. "
                f"Top groups: {', '.join(f'{g}({c})' for g, c in top_groups)}."
            ),
            "iocs": self._format_ioc_table(iocs[:30]),
            "techniques": [],
            "stats": stats,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        report["raw_markdown"] = self._render_markdown(report)
        report_id = await self.db.save_report(report)
        report["id"] = report_id
        return report

    # ── Private helpers ───────────────────────────────────────────────────────

    def _summarize_iocs(self, iocs: List[Dict]) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for ioc in iocs:
            t = ioc.get("ioc_type", "other")
            summary[t] = summary.get(t, 0) + 1
        return summary

    def _extract_malware(self, iocs: List[Dict]) -> List[str]:
        seen = {}
        for ioc in iocs:
            m = ioc.get("malware", "").strip()
            if m:
                seen[m] = seen.get(m, 0) + 1
        return [k for k, _ in sorted(seen.items(), key=lambda x: x[1], reverse=True)]

    def _extract_countries(self, victims: List[Dict]) -> List[str]:
        seen = {}
        for v in victims:
            c = v.get("country", "").strip().upper()
            if c:
                seen[c] = seen.get(c, 0) + 1
        return [k for k, _ in sorted(seen.items(), key=lambda x: x[1], reverse=True)[:10]]

    def _extract_industries(self, victims: List[Dict]) -> List[str]:
        seen = {}
        for v in victims:
            ind = v.get("industry", "").strip()
            if ind:
                seen[ind] = seen.get(ind, 0) + 1
        return [k for k, _ in sorted(seen.items(), key=lambda x: x[1], reverse=True)[:10]]

    def _extract_cves(self, iocs: List[Dict]) -> List[str]:
        return [
            ioc["ioc"] for ioc in iocs
            if ioc.get("ioc_type") == "cve"
        ][:10]

    def _infer_techniques(self, iocs: List[Dict]) -> List[str]:
        techniques = set()
        for ioc in iocs:
            tags_raw = ioc.get("tags", "[]")
            if isinstance(tags_raw, str):
                try:
                    tags = json.loads(tags_raw)
                except Exception:
                    tags = []
            else:
                tags = tags_raw or []

            for tag in tags:
                for keyword, tids in TAG_TO_TECHNIQUE.items():
                    if keyword in tag.lower():
                        techniques.update(tids)
        return sorted(techniques)

    def _format_ioc_table(self, iocs: List[Dict]) -> List[Dict[str, str]]:
        return [
            {
                "ioc": ioc["ioc"],
                "type": ioc.get("ioc_type", ""),
                "malware": ioc.get("malware", ""),
                "confidence": ioc.get("confidence_label", ""),
                "last_seen": ioc.get("last_seen", ""),
                "sources": ioc.get("source_count", 1),
            }
            for ioc in iocs
        ]

    def _build_summary(
        self, actor, ioc_counts, victim_count, malware, days
    ) -> str:
        ioc_total = sum(ioc_counts.values())
        malware_str = ", ".join(malware[:3]) if malware else "unknown"
        return (
            f"{actor} is an active threat actor observed over the past {days} days. "
            f"The platform detected {ioc_total} associated IOCs across "
            f"{len(ioc_counts)} indicator types. "
            f"Primary malware/tools: {malware_str}. "
            f"{victim_count} victims attributed to this actor in the monitoring window."
        )

    def _build_impact(self, victim_count, ioc_counts, countries) -> str:
        country_str = ", ".join(countries[:5]) if countries else "multiple regions"
        ioc_total = sum(ioc_counts.values())
        return (
            f"{victim_count} confirmed victims identified. "
            f"Infrastructure: {ioc_total} active IOCs. "
            f"Geographic targeting: {country_str}."
        )

    def _render_markdown(self, report: Dict[str, Any]) -> str:
        lines = [
            f"# {report['title']}",
            f"**Generated:** {report['generated_at']}",
            "",
            "## Summary",
            report.get("summary", ""),
            "",
            "## Threat Actor",
            report.get("threat_actor", "Unknown"),
            "",
            "## Associated Malware",
            report.get("malware", "N/A"),
            "",
        ]

        countries = report.get("targeted_countries", [])
        lines += [
            "## Targeted Countries",
            ", ".join(countries) if countries else "N/A",
            "",
        ]

        industries = report.get("targeted_industries", [])
        lines += [
            "## Targeted Industries",
            ", ".join(industries) if industries else "N/A",
            "",
        ]

        cves = report.get("cves", [])
        lines += [
            "## CVEs / Vulnerabilities",
            ", ".join(cves) if cves else "N/A",
            "",
            "## Impact",
            report.get("impact", ""),
            "",
        ]

        iocs = report.get("iocs", [])
        if iocs:
            lines += ["## IOC Table", "| IOC | Type | Malware | Confidence | Last Seen |", "|-----|------|---------|------------|-----------|"]
            for ioc in iocs[:30]:
                lines.append(
                    f"| `{ioc['ioc']}` | {ioc['type']} | {ioc.get('malware','')} "
                    f"| {ioc.get('confidence','')} | {ioc.get('last_seen','')} |"
                )
            lines.append("")

        techniques = report.get("techniques", [])
        if techniques:
            lines += ["## MITRE ATT&CK Techniques", "| ID | Name |", "|----|------|"]
            for t in techniques:
                lines.append(f"| {t['id']} | {t['name']} |")
            lines.append("")

        return "\n".join(lines)
