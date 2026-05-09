"""api/routes.py — Core FastAPI routes for CyberXTron TIP v2.2"""
import json
import logging
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger("api.routes")
router = APIRouter()

_db         = None
_scheduler  = None
_report_gen = None
_validator  = None

def get_db():        return _db
def get_scheduler(): return _scheduler


class AlertAckRequest(BaseModel):
    alert_id: int

class ReportRequest(BaseModel):
    type: str = "summary"
    threat_actor: Optional[str] = None
    days: int = 7


@router.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.4.0", "platform": "CyberXTron TIP"}


@router.get("/api/stats")
async def stats():
    return await _db.get_stats()


# ── IOCs ───────────────────────────────────────────────────────────────────────
@router.get("/api/iocs")
async def list_iocs(
    page:         int            = Query(1, ge=1),
    page_size:    int            = Query(50, ge=1, le=10000),
    ioc_type:     Optional[str]  = None,
    threat_actor: Optional[str]  = None,
    malware:      Optional[str]  = None,
    source:       Optional[str]  = None,
    confidence:   Optional[str]  = None,
    date_from:    Optional[str]  = None,
    date_to:      Optional[str]  = None,
    search:       Optional[str]  = None,
):
    return await _db.get_iocs(
        page=page, page_size=page_size, ioc_type=ioc_type,
        threat_actor=threat_actor, malware=malware, source=source,
        confidence=confidence, date_from=date_from, date_to=date_to, search=search,
    )


@router.get("/api/iocs/{ioc_id}/abuseipdb")
async def check_ioc_abuseipdb(ioc_id: int):
    """On-demand AbuseIPDB check for an IP, Domain or URL IOC."""
    import os
    import aiohttp
    import socket
    from urllib.parse import urlparse
    ioc = await _db.get_ioc_by_id(ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    
    ioc_type = ioc.get("ioc_type")
    ioc_val = ioc["ioc"]
    ip_to_check = ioc_val

    if ioc_type not in ("ip", "domain", "url"):
        return {"supported": False, "reason": "Only IP, Domain, and URL types can be checked against AbuseIPDB."}
    
    if ioc_type in ("domain", "url"):
        try:
            hostname = urlparse(ioc_val).hostname if ioc_type == "url" else ioc_val
            if not hostname: hostname = ioc_val.split('/')[0]
            ip_to_check = socket.gethostbyname(hostname)
        except Exception as e:
            return {"supported": False, "reason": f"Could not resolve hostname '{hostname}': {str(e)}"}

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {"supported": False, "reason": "ABUSEIPDB_API_KEY not configured in .env"}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip_to_check, "maxAgeInDays": "90", "verbose": "true"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    d = data.get("data", {})
                    return {
                        "supported": True,
                        "ip": ip_to_check,
                        "original_ioc": ioc_val,
                        "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
                        "totalReports": d.get("totalReports", 0),
                        "numDistinctUsers": d.get("numDistinctUsers", 0),
                        "countryCode": d.get("countryCode", ""),
                        "usageType": d.get("usageType", ""),
                        "isp": d.get("isp", ""),
                        "domain": d.get("domain", ""),
                        "isWhitelisted": d.get("isWhitelisted", False),
                        "lastReportedAt": d.get("lastReportedAt", "")
                    }
                elif resp.status == 429:
                    return {"supported": False, "reason": "AbuseIPDB rate limit reached. Try again later."}
                else:
                    return {"supported": False, "reason": f"AbuseIPDB returned HTTP {resp.status}"}
    except Exception as e:
        return {"supported": False, "reason": str(e)}


@router.get("/api/iocs/{ioc_id}/malwarebazaar")
async def check_ioc_malwarebazaar(ioc_id: int):
    """On-demand MalwareBazaar check for a hash IOC."""
    import aiohttp
    ioc = await _db.get_ioc_by_id(ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    
    ioc_type = ioc.get("ioc_type")
    if ioc_type not in ("md5", "sha256", "sha1"):
        return {"supported": False, "reason": "Only hash types (MD5, SHA256, SHA1) can be checked against MalwareBazaar."}
    
    h = ioc["ioc"]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": h},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("query_status") == "ok":
                        d = data.get("data", [{}])[0]
                        return {
                            "supported": True,
                            "hash": h,
                            "file_name": d.get("file_name"),
                            "file_type": d.get("file_type"),
                            "file_size": d.get("file_size"),
                            "signature": d.get("signature"),
                            "tags": d.get("tags", []),
                            "delivery_method": d.get("delivery_method"),
                            "first_seen": d.get("first_seen"),
                            "last_seen": d.get("last_seen")
                        }
                    else:
                        return {"supported": False, "reason": f"MalwareBazaar: {data.get('query_status', 'No results')}"}
                else:
                    return {"supported": False, "reason": f"MalwareBazaar returned HTTP {resp.status}"}
    except Exception as e:
        return {"supported": False, "reason": str(e)}


@router.post("/api/verify-intelligence")
async def trigger_verification(background_tasks: BackgroundTasks):
    from engine.validator import IOCValidator
    
    async def run_sweep():
        validator = IOCValidator(_db)
        await validator.run_cleanup_sweep(verify_only=True) # Only updates confidence
        
    background_tasks.add_task(run_sweep)
    return {"status": "triggered", "message": "Mass intelligence verification started in the background."}


@router.get("/api/iocs/{ioc_id}")
async def get_ioc(ioc_id: int):
    ioc = await _db.get_ioc_by_id(ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    for f in ("sources", "tags", "raw_data"):
        if isinstance(ioc.get(f), str):
            try:    ioc[f] = json.loads(ioc[f])
            except: ioc[f] = []
    return ioc

@router.post("/api/iocs/deduplicate")
async def trigger_deduplication(background_tasks: BackgroundTasks):
    from engine.deduplicator import IOCDeduplicator
    
    async def run_dedup():
        dedup = IOCDeduplicator(_db)
        await dedup.run_subsumption_sweep()
        
    background_tasks.add_task(run_dedup)
    return {"status": "triggered", "message": "IOC Deduplication started in the background."}


@router.post("/api/iocs/sanitize")
async def trigger_sanitization(background_tasks: BackgroundTasks):
    from engine.validator import IOCValidator
    
    async def run_sweep():
        validator = IOCValidator(_db)
        await validator.run_cleanup_sweep(verify_only=False) # Purges clean items
        
    background_tasks.add_task(run_sweep)
    return {"status": "triggered", "message": "Automated IOC Sanitization sweep started in the background."}




# ── Victims ─────────────────────────────────────────────────────────────────────
@router.get("/api/victims")
async def list_victims(
    page:       int           = Query(1, ge=1),
    page_size:  int           = Query(50, ge=1, le=10000),
    group_name: Optional[str] = None,
    country:    Optional[str] = None,
    search:     Optional[str] = None,
    date_from:  Optional[str] = None,
    source:     Optional[str] = None,
):
    return await _db.get_victims(
        page=page, page_size=page_size,
        group_name=group_name, country=country,
        search=search, date_from=date_from, source=source,
    )


# ── Alerts ──────────────────────────────────────────────────────────────────────
@router.get("/api/alerts")
async def list_alerts(
    unacknowledged_only: bool = Query(False),
    alert_type: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    return await _db.get_alerts(unacknowledged_only=unacknowledged_only, alert_type=alert_type, limit=limit)


@router.post("/api/alerts/acknowledge")
async def ack_alert(req: AlertAckRequest):
    await _db.acknowledge_alert(req.alert_id)
    return {"status": "ok", "alert_id": req.alert_id}


@router.post("/api/alerts/acknowledge-all")
async def ack_all():
    alerts = await _db.get_alerts(unacknowledged_only=True, limit=5000)
    for a in alerts:
        await _db.acknowledge_alert(a["id"])
    return {"status": "ok", "acknowledged": len(alerts)}


# ── Sources & Scheduler ─────────────────────────────────────────────────────────
@router.get("/api/sources")
async def list_sources():
    return await _db.get_sources()


@router.api_route("/api/refresh", methods=["GET", "POST"])
async def trigger_refresh(background_tasks: BackgroundTasks):
    if not _scheduler:
        raise HTTPException(503, "Scheduler not ready")
    background_tasks.add_task(_scheduler.run_all_now)
    return {"status": "triggered", "message": "All connectors running in background"}


@router.post("/api/database/sanitize")
async def sanitize_database(background_tasks: BackgroundTasks):
    if not _validator:
        raise HTTPException(503, "Validator not ready")
    background_tasks.add_task(_validator.run_cleanup_sweep)
    return {"status": "triggered", "message": "Database sanitization sweep started in background"}


@router.get("/api/scheduler/status")
async def scheduler_status():
    if not _scheduler:
        return {"jobs": []}
    return {"jobs": _scheduler.get_job_status()}


# ── Reports ─────────────────────────────────────────────────────────────────────
@router.get("/api/reports")
async def list_reports(limit: int = Query(20, ge=1, le=100)):
    return await _db.get_reports(limit=limit)


@router.get("/api/reports/{report_id}/markdown")
async def get_report_md(report_id: int):
    md = await _db.get_report_markdown(report_id)
    if md is None:
        raise HTTPException(404, "Report not found")
    return {"id": report_id, "markdown": md}


@router.post("/api/reports/generate")
async def generate_report(req: ReportRequest):
    if not _report_gen:
        raise HTTPException(503, "Report generator not ready")
    if req.type == "actor":
        if not req.threat_actor:
            raise HTTPException(400, "threat_actor required")
        return await _report_gen.generate_from_actor(req.threat_actor)
    return await _report_gen.generate_summary_report(days=req.days)


# ── Logs ─────────────────────────────────────────────────────────────────────────
@router.get("/api/logs")
async def list_logs(
    limit: int = Query(300, ge=1, le=2000),
    level: Optional[str] = None,
):
    return await _db.get_logs(limit=limit, level=level)
