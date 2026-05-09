"""connectors/urlhaus.py — URLHaus malicious URL feed. Fixed & working."""
from typing import Any, Dict, List
from connectors.base import BaseConnector, now_iso
from config import settings
from config import settings

def _is_ip(h):
    p = h.split(".")
    try: return len(p)==4 and all(0<=int(x)<=255 for x in p)
    except: return False

class URLHausConnector(BaseConnector):
    name = "urlhaus"
    display_name = "URLHaus (Abuse.ch)"
    tier = 1
    API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/"

    async def fetch(self) -> List[Dict[str, Any]]:
        headers = {"Content-Type": "application/json"}
        api_key = getattr(settings, "URLHAUS_API_KEY", None)
        if api_key:
            headers["API-KEY"] = api_key

        # Try JSON API first
        data = await self._post(self.API_URL, json_data={}, headers=headers)
        if not data:
            data = await self._post("https://urlhaus-api.abuse.ch/v1/", json_data={"query": "get_urls", "limit": 200}, headers=headers)

        records = []
        entries = []
        if isinstance(data, dict):
            entries = data.get("urls", []) or []
        elif isinstance(data, list):
            entries = data

        if not entries:
            # CSV fallback
            return await self._csv_fallback()

        for e in entries:
            url = (e.get("url") or "").strip()
            if not url or not url.startswith("http"): continue
            threat = (e.get("threat") or "").lower()
            tags = [t.lower() for t in (e.get("tags") or []) if t]
            malware = threat or (tags[0] if tags else "malware")
            date_added = e.get("date_added") or now_iso()
            host = e.get("host", "")
            records.append(self.make_ioc(source=self.name, ioc=url, ioc_type="url",
                malware=malware, tags=tags, confidence="medium",
                first_seen=date_added, last_seen=date_added,
                description=f"URLHaus: {threat} | reporter:{e.get('reporter','')}",
                raw=e))
            if host:
                itype = "ip" if _is_ip(host) else "domain"
                records.append(self.make_ioc(source=self.name, ioc=host, ioc_type=itype,
                    malware=malware, tags=tags+["urlhaus_host"], confidence="medium",
                    first_seen=date_added, last_seen=date_added,
                    description="URLHaus malware hosting host"))

        self.logger.info("URLHaus: fetched %d records", len(records))
        return records

    async def _csv_fallback(self):
        text = await self._get("https://urlhaus.abuse.ch/downloads/csv_recent/")
        if not text or not isinstance(text, str): return []
        records = []
        for line in text.splitlines():
            if line.startswith("#") or not line.strip(): continue
            parts = [p.strip().strip('"') for p in line.split('","')]
            if len(parts) < 5: continue
            url = parts[2] if len(parts)>2 else ""
            date = parts[1] if len(parts)>1 else now_iso()
            threat = parts[4] if len(parts)>4 else ""
            if url.startswith("http"):
                records.append(self.make_ioc(source=self.name, ioc=url, ioc_type="url",
                    malware=threat, tags=[threat] if threat else [], confidence="medium",
                    first_seen=date, last_seen=date, description=f"URLHaus CSV: {threat}"))
        return records[:300]
