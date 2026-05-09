"""
engine/alerting.py — Smart alert engine.
Fixed: generate alerts for ALL high+medium confidence IOCs, not just new ones.
Also generates alerts when dark web victims discovered.
"""
import logging
from typing import Any, Dict
from database.db import Database
from config import settings

logger = logging.getLogger("engine.alerting")


class AlertingEngine:
    def __init__(self, db: Database):
        self.db = db
        self._threshold = settings.ALERT_MIN_CONFIDENCE

    def _conf_num(self, c) -> float:
        if isinstance(c, (int, float)): return float(c)
        return {"high": 0.85, "medium": 0.60, "low": 0.35}.get(str(c), 0.35)

    async def evaluate_ioc(self, ioc_id: int, is_new: bool, record: Dict[str, Any]):
        """Generate alert for high-confidence new IOCs."""
        if not is_new: return
        confidence = self._conf_num(record.get("confidence", 0))
        if confidence < self._threshold: return

        ioc_val    = record.get("ioc", "")
        ioc_type   = record.get("ioc_type", "")
        malware    = record.get("malware", "")
        actor      = record.get("threat_actor", "unknown")
        source     = record.get("source", "")
        severity   = self._severity(confidence, ioc_type, malware, actor)

        title = f"[{severity.upper()}] New {ioc_type.upper()} IOC Detected"
        if malware: title += f" — {malware}"
        desc  = (
            f"IOC: {ioc_val}\n"
            f"Type: {ioc_type} | Source: {source} | Confidence: {confidence:.0%}"
        )
        if actor and actor != "unknown": desc += f"\nActor: {actor}"

        await self.db.create_alert({
            "alert_type": "new_ioc",
            "title": title,
            "description": desc,
            "severity": severity,
            "ioc_id": ioc_id,
            "source": source,
        })

    async def evaluate_victim(self, victim_id: int, is_new: bool, record: Dict[str, Any]):
        """Every new ransomware victim = high priority alert."""
        if not is_new: return
        group  = record.get("group_name", "Unknown")
        victim = record.get("victim_name", "Unknown")
        country  = record.get("country", "")
        industry = record.get("industry", "")
        source   = record.get("source", "")

        title = f"[ALERT] New Ransomware Victim: {victim}"
        desc  = f"Group: {group}\nVictim: {victim}"
        if country:  desc += f"\nCountry: {country}"
        if industry: desc += f"\nIndustry: {industry}"
        if source:   desc += f"\nSource: {source}"

        await self.db.create_alert({
            "alert_type": "new_victim",
            "title": title,
            "description": desc,
            "severity": "high",
            "victim_id": victim_id,
            "source": source,
        })
        logger.info("Alert: new victim %s / %s", group, victim)

    async def generate_startup_alerts(self, db: Database):
        """
        Generate alerts for existing high-confidence IOCs on startup
        if no alerts exist yet. Ensures the Alerts tab is never empty.
        """
        existing = await db.get_alerts(limit=1)
        if existing: return  # Already have alerts

        # Create alerts for top high-confidence IOCs
        iocs_data = await db.get_iocs(confidence="high", page_size=20)
        for ioc in iocs_data.get("items", []):
            conf = self._conf_num(ioc.get("confidence", 0))
            sev  = self._severity(conf, ioc.get("ioc_type",""), ioc.get("malware",""), ioc.get("threat_actor",""))
            await db.create_alert({
                "alert_type": "high_confidence",
                "title": f"[{sev.upper()}] High-Confidence IOC: {ioc['ioc'][:60]}",
                "description": (
                    f"Type: {ioc['ioc_type']} | Confidence: {conf:.0%}\n"
                    f"Malware: {ioc.get('malware','?')} | Sources: {ioc.get('source_count',1)}"
                ),
                "severity": sev,
                "ioc_id": ioc["id"],
                "source": "startup_scan",
            })

        # Create alerts for existing victims
        victims_data = await db.get_victims(page_size=20)
        for v in victims_data.get("items", []):
            await db.create_alert({
                "alert_type": "new_victim",
                "title": f"[ALERT] Ransomware Victim Tracked: {v['victim_name'][:60]}",
                "description": (
                    f"Group: {v['group_name']}\n"
                    f"Country: {v.get('country','?')} | Industry: {v.get('industry','?')}"
                ),
                "severity": "high",
                "victim_id": v["id"],
                "source": v.get("source",""),
            })

        logger.info("Generated startup alerts from existing data")

    def _severity(self, conf, ioc_type, malware, actor) -> str:
        score = conf
        HIGH_RISK = {"ransomware","rat","c2","botnet","cobalt strike","emotet",
                     "qakbot","lockbit","blackcat","conti","stealer","icedid"}
        ml = (malware or "").lower()
        if any(h in ml for h in HIGH_RISK): score += 0.15
        if actor and actor not in ("unknown", ""): score += 0.08
        if ioc_type == "ip": score += 0.05
        if score >= 0.92: return "critical"
        if score >= 0.78: return "high"
        if score >= 0.60: return "medium"
        return "low"
