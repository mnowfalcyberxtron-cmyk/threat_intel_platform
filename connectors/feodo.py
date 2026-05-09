"""connectors/feodo.py — Feodo Tracker C2 IPs. Fixed & working."""
from typing import Any, Dict, List
from connectors.base import BaseConnector, now_iso

class FeodoConnector(BaseConnector):
    name = "feodo"
    display_name = "Feodo Tracker (Abuse.ch)"
    tier = 1
    JSON_URL  = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    CSV_URL   = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.csv"

    async def fetch(self) -> List[Dict[str, Any]]:
        data = await self._get(self.JSON_URL)
        if isinstance(data, list): return self._parse(data)
        if isinstance(data, dict): return self._parse(data.get("data", []))
        return await self._csv_fallback()

    def _parse(self, entries):
        records = []
        for e in entries:
            ip = (e.get("ip_address") or "").strip()
            if not ip: continue
            malware = (e.get("malware") or "botnet_c2").strip()
            country = e.get("country","")
            port = e.get("port","")
            as_name = e.get("as_name","")
            first_seen = e.get("first_seen") or now_iso()
            last_online = e.get("last_online") or first_seen
            tags = ["c2","botnet",malware.lower()]
            if country: tags.append(f"country:{country.lower()}")
            records.append(self.make_ioc(
                source=self.name, ioc=ip, ioc_type="ip", malware=malware,
                tags=tags, confidence="high",
                first_seen=first_seen, last_seen=last_online,
                description=f"Feodo C2 | {malware} | port:{port} | AS:{as_name}", raw=e))
        self.logger.info("Feodo: fetched %d C2 IPs", len(records))
        return records

    async def _csv_fallback(self):
        text = await self._get(self.CSV_URL)
        if not text or not isinstance(text, str): return []
        records = []
        for line in text.splitlines():
            if line.startswith("#") or not line.strip(): continue
            parts = line.split(",")
            ip = parts[1].strip() if len(parts)>1 else parts[0].strip()
            if not ip or not "." in ip: continue
            malware = parts[3].strip() if len(parts)>3 else "botnet_c2"
            first_seen = parts[0].strip() if len(parts)>3 else now_iso()
            records.append(self.make_ioc(
                source=self.name, ioc=ip, ioc_type="ip", malware=malware,
                tags=["c2","botnet"], confidence="high",
                first_seen=first_seen, last_seen=first_seen,
                description=f"Feodo Tracker C2 | {malware}"))
        return records
