"""connectors/otx.py — AlienVault OTX Threat Intelligence Connector."""
import logging
from typing import Any, Dict, List
from datetime import datetime, timezone

from connectors.base import BaseConnector, now_iso
from config import settings

logger = logging.getLogger("connectors.otx")

# Mapping OTX indicator types to our standard types
OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "CVE": "cve"
}

class OTXConnector(BaseConnector):
    name = "otx"
    display_name = "AlienVault OTX"
    tier = 1
    API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    async def fetch(self) -> List[Dict[str, Any]]:
        api_key = getattr(settings, "OTX_API_KEY", None)
        if not api_key:
            self.logger.warning("OTX_API_KEY not set in config, skipping OTX connector")
            return []

        headers = {
            "X-OTX-API-KEY": api_key,
            "User-Agent": "ThreatIntel-TIP/2.4"
        }
        
        # We fetch the first page of subscribed pulses (usually 20-50 pulses)
        params = {"limit": 20}
        
        data = await self._get(self.API_URL, headers=headers, params=params)
        if not data or "results" not in data:
            self.logger.warning("OTX: No data returned or invalid format")
            return []
            
        pulses = data["results"]
        records = []
        
        for pulse in pulses:
            campaign_name = pulse.get("name", "").strip()
            pulse_tags = [t.lower() for t in pulse.get("tags", [])]
            indicators = pulse.get("indicators", [])
            modified = pulse.get("modified", "")
            if not modified:
                modified = now_iso()
                
            pulse_id = pulse.get("id", "")
            
            # Use pulse name as campaign name
            campaign = campaign_name
            
            # Combine tags
            tags = ["otx", "alienvault"]
            tags.extend(pulse_tags)
            tags = list(set(tags))
            
            for ind in indicators:
                raw_type = ind.get("type", "")
                ioc_val = ind.get("indicator", "").strip()
                
                if not ioc_val or not raw_type:
                    continue
                    
                ioc_type = OTX_TYPE_MAP.get(raw_type)
                if not ioc_type:
                    continue  # Skip unsupported types
                    
                records.append(
                    self.make_ioc(
                        source=self.name,
                        ioc=ioc_val,
                        ioc_type=ioc_type,
                        campaign=campaign,
                        tags=tags,
                        confidence="high",  # OTX subscribed pulses are generally high confidence
                        first_seen=modified,
                        last_seen=modified,
                        description=f"OTX Pulse: {campaign_name} (ID: {pulse_id})",
                        raw=ind
                    )
                )
                
        self.logger.info("OTX: Fetched %d IOCs from %d pulses", len(records), len(pulses))
        return records
