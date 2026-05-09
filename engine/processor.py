"""engine/processor.py — IOC processor with alerting wired in."""
import logging
from typing import Any, Dict, List
from database.db import Database
from engine.alerting import AlertingEngine
from engine.abuseipdb import check_ip_confidence

logger = logging.getLogger("engine.processor")


class IOCProcessor:
    def __init__(self, db: Database):
        self.db      = db
        self.alerter = AlertingEngine(db)

    def _clabel(self, s: float) -> str:
        return "high" if s>=0.75 else "medium" if s>=0.50 else "low"

    async def process_batch(self, records: List[Dict[str, Any]], source: str) -> Dict[str, int]:
        stats = {"new": 0, "updated": 0, "skipped": 0,
                 "victims_new": 0, "victims_updated": 0}
        for rec in records:
            try:
                rtype = rec.get("type", "ioc")
                if rtype == "ioc":
                    r = await self._process_ioc(rec)
                    stats[r] = stats.get(r, 0) + 1
                elif rtype == "victim":
                    vid, is_new = await self.db.upsert_victim(rec)
                    if is_new:
                        stats["victims_new"] += 1
                        await self.alerter.evaluate_victim(vid, True, rec)
                    else:
                        stats["victims_updated"] += 1
            except Exception as e:
                logger.debug("Record error from %s: %s", source, e)
                stats["skipped"] += 1
        return stats

    async def _process_ioc(self, rec: Dict[str, Any]) -> str:
        ioc   = str(rec.get("ioc", "")).strip().lower()
        itype = str(rec.get("ioc_type", "")).strip().lower()
        if not ioc or not itype: return "skipped"

        # Normalize
        ioc   = self._normalize(ioc, itype)
        if not ioc or not self._validate(ioc, itype): return "skipped"

        rec2 = {**rec, "ioc": ioc, "ioc_type": itype}
        ioc_id, is_new = await self.db.upsert_ioc(rec2)
        if not ioc_id: return "skipped"

        # Alert on new high-confidence IOCs
        if is_new:
            conf = rec.get("confidence", "low")
            conf_num = {"high": 0.85, "medium": 0.60, "low": 0.35}.get(
                str(conf), float(conf) if isinstance(conf, (int,float)) else 0.35)
                
            # --- AbuseIPDB Integration (Confidence Check) ---
            if itype == "ip":
                abuse_score = await check_ip_confidence(ioc)
                if abuse_score >= 0.90:
                    conf_num = 0.95
                    label = "critical"
                elif abuse_score >= 0.70:
                    conf_num = max(conf_num, 0.90)
                    label = "high"
                elif abuse_score >= 0.40:
                    conf_num = max(conf_num, 0.70)
                    label = "medium"
                else:
                    label = self._clabel(conf_num)

                if abuse_score >= 0.40:
                    logger.info(f"Boosted confidence of {ioc} to {conf_num} (Score: {abuse_score})")
                    await self.db._conn.execute(
                        "UPDATE iocs SET confidence=?, confidence_label=? WHERE id=?", 
                        (conf_num, label, ioc_id)
                    )
                    await self.db._conn.commit()

            if conf_num >= 0.65:
                await self.alerter.evaluate_ioc(ioc_id, True, rec2)

        return "new" if is_new else "updated"

    @staticmethod
    def _normalize(val: str, itype: str) -> str:
        if itype in ("md5","sha1","sha256"): return val.lower()
        if itype == "ip":
            if ":" in val: val = val.rsplit(":",1)[0]
            return val.strip()
        if itype == "domain":
            val = val.replace("https://","").replace("http://","").split("/")[0].strip()
            if val.startswith("www."): val = val[4:]
            return val.lower()
        if itype == "url":
            val = val.replace("hxxp://","http://").replace("hxxps://","https://")
            return val.replace("[.]",".")
        if itype == "cve": return val.upper()
        return val

    @staticmethod
    def _validate(val: str, itype: str) -> bool:
        if not val or len(val) < 3 or len(val) > 2000: return False
        if itype == "ip":
            p = val.split(".")
            if len(p) != 4: return False
            try: return all(0 <= int(x) <= 255 for x in p)
            except: return False
        if itype == "domain": return "." in val and len(val) > 3
        if itype == "md5":    return len(val)==32  and all(c in "0123456789abcdef" for c in val)
        if itype == "sha256": return len(val)==64  and all(c in "0123456789abcdef" for c in val)
        if itype == "sha1":   return len(val)==40  and all(c in "0123456789abcdef" for c in val)
        if itype == "url":    return val.startswith("http") and "." in val
        if itype == "cve":    return val.upper().startswith("CVE-")
        return True
