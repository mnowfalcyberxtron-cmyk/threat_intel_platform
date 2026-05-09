"""connectors/threatfox.py — ThreatFox with Windows SSL fix."""
from typing import Any, Dict, List
from connectors.base import BaseConnector, now_iso
from config import settings
from config import settings

TYPE_MAP = {
    "ip:port":"ip","domain":"domain","url":"url",
    "md5_hash":"md5","sha256_hash":"sha256","sha1_hash":"sha1",
}

class ThreatFoxConnector(BaseConnector):
    name = "threatfox"
    display_name = "ThreatFox (Abuse.ch)"
    tier = 1
    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    async def fetch(self) -> List[Dict[str, Any]]:
        headers = {"Content-Type": "application/json", "User-Agent": "CyberXTron-TIP/2.2"}
        api_key = getattr(settings, "THREATFOX_API_KEY", None)
        if api_key:
            headers["API-KEY"] = api_key

        for days in [1, 3]:
            data = await self._post(self.API_URL,
                json_data={"query": "get_iocs", "days": days},
                headers=headers)
            if data and data.get("query_status") == "ok" and data.get("data"):
                return self._parse(data["data"])
        self.logger.warning("ThreatFox: no data returned")
        return []

    def _parse(self, entries):
        records = []
        for e in entries or []:
            raw_type = e.get("ioc_type","")
            ioc_type = TYPE_MAP.get(raw_type, raw_type)
            ioc_val  = (e.get("ioc") or "").strip()
            if not ioc_val or not ioc_type: continue
            if raw_type == "ip:port" and ":" in ioc_val:
                ioc_val = ioc_val.rsplit(":",1)[0]
            conf_lvl = int(e.get("confidence_level") or 50)
            conf = "high" if conf_lvl>=75 else "medium" if conf_lvl>=40 else "low"
            malware = (e.get("malware") or "")
            family  = malware.split(".")[-1] if "." in malware else malware
            tags    = [t.lower() for t in (e.get("tags") or []) if t]
            tt      = e.get("threat_type","")
            if tt and tt not in tags: tags.append(tt.lower())
            fs = e.get("first_seen") or now_iso()
            ls = e.get("last_seen") or fs
            records.append(self.make_ioc(
                source=self.name, ioc=ioc_val, ioc_type=ioc_type,
                malware=family, tags=tags, confidence=conf,
                first_seen=fs, last_seen=ls,
                description=f"ThreatFox: {tt}|{malware}|{conf_lvl}%",
                raw=e))
        self.logger.info("ThreatFox: %d IOCs", len(records))
        return records
