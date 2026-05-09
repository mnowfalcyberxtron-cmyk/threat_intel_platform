import logging
import os
import httpx
import json
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import List, Dict, Any
from database.db import Database

logger = logging.getLogger("engine.validator")

class IOCValidator:
    def __init__(self, db: Database):
        self.db = db
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        # Use ThreatFox key as a fallback for other abuse.ch services if specific keys are missing
        self.abuse_ch_key = os.getenv("THREATFOX_API_KEY", "").strip()

    async def run_cleanup_sweep(self, verify_only: bool = False):
        """Main sweep logic to validate and purge clean IOCs (unless verify_only is True)."""
        logger.info(f"Starting automated IOC validation sweep (verify_only={verify_only})...")
        
        # 1. Validate IPs, Domains, and URLs using AbuseIPDB (resolving where needed)
        if self.abuseipdb_key:
            await self._validate_with_abuseipdb(verify_only=verify_only)
        
        # 2. Validate Domains/URLs using URLHaus
        if self.abuse_ch_key:
            await self._validate_domains(verify_only=verify_only)
            
        # 3. Validate Hashes using MalwareBazaar
        if self.abuse_ch_key:
            await self._validate_hashes(verify_only=verify_only)
        
        logger.info("IOC validation sweep complete.")

    async def _validate_with_abuseipdb(self, verify_only: bool = False):
        """Check IPs, Domains, and URLs against AbuseIPDB and update confidence."""
        # Check IPs first, then Domains/URLs (resolving them)
        query = "SELECT id, ioc, ioc_type FROM iocs WHERE ioc_type IN ('ip', 'domain', 'url') ORDER BY last_seen ASC LIMIT 100"
        rows = await self.db.execute_read(query)
        if not rows: return

        async with httpx.AsyncClient(timeout=30.0) as client:
            for row in rows:
                ioc_id, ioc_val, ioc_type = row['id'], row['ioc'], row['ioc_type']
                ip_to_check = ioc_val
                
                # If it's a domain or URL, resolve to IP
                if ioc_type in ('domain', 'url'):
                    try:
                        hostname = urlparse(ioc_val).hostname if ioc_type == 'url' else ioc_val
                        if not hostname: hostname = ioc_val.split('/')[0] # Fallback for malformed
                        ip_to_check = socket.gethostbyname(hostname)
                    except Exception:
                        continue # Can't resolve, skip AbuseIPDB check for this item

                try:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip_to_check, "maxAgeInDays": 90},
                        headers={"Key": self.abuseipdb_key, "Accept": "application/json"}
                    )
                    if resp.status_code == 200:
                        d = resp.json().get("data", {})
                        reports = d.get("totalReports", 0)
                        reporters = d.get("numDistinctUsers", 0)
                        score = d.get("abuseConfidenceScore", 0)
                        
                        # Rule: If detection is 0 (no reports), and not verify_only, AND it's an IP, remove it
                        # (We don't purge domains/URLs based on AbuseIPDB alone as they might be clean IPs hosting bad domains)
                        if ioc_type == 'ip' and reports == 0 and reporters == 0 and not verify_only:
                            logger.info(f"Purging clean IP: {ioc_val} (Zero detections)")
                            await self.db.execute_write("DELETE FROM iocs WHERE id = ?", (ioc_id,))
                            continue
                            
                        # Update confidence
                        conf = max(0.1, score / 100.0)
                        if reporters > 5: conf = min(1.0, conf + 0.1)
                        label = "high" if conf >= 0.8 else "medium" if conf >= 0.4 else "low"
                        
                        # Enrichment
                        usage = d.get("usageType", "").lower()
                        new_tags = []
                        if "data center" in usage or "hosting" in usage: new_tags.append("infrastructure:datacenter")
                        if d.get("isWhitelisted"): new_tags.append("whitelisted")
                        
                        # Update database
                        async with self.db._conn.execute("SELECT tags, raw_data FROM iocs WHERE id = ?", (ioc_id,)) as cur:
                            r = await cur.fetchone()
                            existing_tags = json.loads(r["tags"] or "[]")
                            existing_raw = json.loads(r["raw_data"] or "{}")
                        
                        for tag in new_tags:
                            if tag not in existing_tags: existing_tags.append(tag)
                        
                        existing_raw["abuseipdb"] = {
                            "source_ip": ip_to_check,
                            "score": score,
                            "reports": reports,
                            "reporters": reporters,
                            "usage": usage,
                            "isp": d.get("isp"),
                            "checked_at": datetime.now(timezone.utc).isoformat()
                        }

                        await self.db.execute_write(
                            "UPDATE iocs SET confidence = ?, confidence_label = ?, tags = ?, raw_data = ?, updated_at = ? WHERE id = ?",
                            (conf, label, json.dumps(existing_tags), json.dumps(existing_raw), datetime.now(timezone.utc).isoformat(), ioc_id)
                        )
                    elif resp.status_code == 429: break
                except Exception as e: logger.error(f"Validation Error ({ioc_val} -> {ip_to_check}): {e}")

    async def _validate_domains(self, verify_only: bool = False):
        """Check domains/URLs against URLHaus (unless verify_only)."""
        if verify_only: return # URLHaus doesn't provide scores, just status. skip in verify_only for now.
        query = "SELECT id, ioc FROM iocs WHERE ioc_type IN ('domain', 'url') ORDER BY last_seen ASC LIMIT 50"
        rows = await self.db.execute_read(query)
        if not rows: return

        async with httpx.AsyncClient(timeout=30.0) as client:
            for row in rows:
                ioc_id, ioc = row['id'], row['ioc']
                try:
                    # URLHaus lookup
                    data = {"url": ioc} if ioc.startswith("http") else {"host": ioc}
                    endpoint = "https://urlhaus-api.abuse.ch/v1/url/" if ioc.startswith("http") else "https://urlhaus-api.abuse.ch/v1/host/"
                    
                    resp = await client.post(endpoint, data=data)
                    if resp.status_code == 200:
                        res = resp.json()
                        # If query_status is 'no_results' or url_status is 'offline'
                        if res.get("query_status") == "no_results" or res.get("url_status") == "offline":
                            logger.info(f"Purging inactive domain/url: {ioc}")
                            await self.db.execute_write("DELETE FROM iocs WHERE id = ?", (ioc_id,))
                except Exception as e: logger.error(f"Domain Validation Error ({ioc}): {e}")

    async def _validate_hashes(self, verify_only: bool = False):
        """Check hashes against MalwareBazaar (unless verify_only)."""
        if verify_only: return # Bazaar doesn't provide scores, just status. skip in verify_only for now.
        query = "SELECT id, ioc FROM iocs WHERE ioc_type IN ('md5', 'sha256', 'sha1') ORDER BY last_seen ASC LIMIT 50"
        rows = await self.db.execute_read(query)
        if not rows: return

        async with httpx.AsyncClient(timeout=30.0) as client:
            for row in rows:
                ioc_id, h = row['id'], row['ioc']
                try:
                    resp = await client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": h})
                    if resp.status_code == 200:
                        res = resp.json()
                        if res.get("query_status") != "ok":
                            logger.info(f"Purging unknown/clean hash: {h}")
                            await self.db.execute_write("DELETE FROM iocs WHERE id = ?", (ioc_id,))
                except Exception as e: logger.error(f"Hash Validation Error ({h}): {e}")

    async def validate_single_ioc(self, ioc_id: int) -> Dict[str, Any]:
        """On-demand validation for a single IOC."""
        # This can be used to manually trigger from UI as well
        query = "SELECT ioc, ioc_type FROM iocs WHERE id = ?"
        row = await self.db.execute_read_one(query, (ioc_id,))
        if not row:
            return {"status": "error", "message": "IOC not found"}
        
        ioc = row['ioc']
        ioc_type = row['ioc_type']
        
        if ioc_type == 'ip' and self.api_key:
            # Re-use logic or call _validate_ips style check
            # For now, just return a check status
            return {"status": "checked", "type": "ip"}
            
        return {"status": "unsupported"}
