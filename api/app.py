"""
api/app.py — FastAPI application for CyberXTron TIP.
All routes: stats, IOCs, victims, alerts, reports, source status, logs.
"""

import json
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from config import settings
from database.db import Database
from engine.scheduler import MonitoringScheduler
from engine.report_engine import ReportEngine

logger = logging.getLogger("api")

# Global singletons
db = Database()
scheduler: Optional[MonitoringScheduler] = None
templates = Jinja2Templates(directory="frontend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup + shutdown lifecycle."""
    global scheduler

    settings.ensure_dirs()
    await db.initialize()
    logger.info("✅ Database ready")

    scheduler = MonitoringScheduler(db)
    scheduler.start()
    logger.info("✅ Monitoring engine started")

    yield

    scheduler.stop()
    await db.close()
    logger.info("Platform shutdown complete")


app = FastAPI(
    title=settings.PLATFORM_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="frontend/static"), name="static")


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    """Platform-wide statistics and overview metrics."""
    stats = await db.get_stats()
    job_stats = scheduler.get_job_stats() if scheduler else {}
    return {
        **stats,
        "scheduler_jobs": job_stats,
        "platform": settings.PLATFORM_NAME,
        "version": settings.VERSION,
    }


# ── IOCs ──────────────────────────────────────────────────────────────────────

@app.get("/api/iocs")
async def get_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = None,
    threat_actor: Optional[str] = None,
    malware: Optional[str] = None,
    source: Optional[str] = None,
    confidence: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    search: Optional[str] = None,
):
    """
    Query IOC intelligence with filters.
    All results are deduplicated, ranked by confidence and recency.
    """
    return await db.get_iocs(
        page=page,
        page_size=page_size,
        ioc_type=ioc_type,
        threat_actor=threat_actor,
        malware=malware,
        source=source,
        confidence=confidence,
        date_from=date_from,
        date_to=date_to,
        search=search,
    )


@app.get("/api/iocs/{ioc_id}")
async def get_ioc(ioc_id: int):
    """Get detailed record for a single IOC."""
    record = await db.get_ioc_by_id(ioc_id)
    if not record:
        raise HTTPException(status_code=404, detail="IOC not found")
    # Parse JSON fields for response
    record["sources"] = json.loads(record.get("sources", "[]"))
    record["tags"] = json.loads(record.get("tags", "[]"))
    record["raw_data"] = json.loads(record.get("raw_data", "{}"))
    return record


# ── Ransomware Victims ────────────────────────────────────────────────────────

@app.get("/api/victims")
async def get_victims(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    group_name: Optional[str] = None,
    country: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
):
    """Query ransomware victim intelligence."""
    return await db.get_victims(
        page=page,
        page_size=page_size,
        group_name=group_name,
        country=country,
        search=search,
        date_from=date_from,
    )


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts(
    unacknowledged_only: bool = False,
    limit: int = Query(100, le=500),
):
    """Get security alerts. High-confidence, low-noise."""
    return await db.get_alerts(
        unacknowledged_only=unacknowledged_only,
        limit=limit,
    )


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    """Mark an alert as acknowledged."""
    await db.acknowledge_alert(alert_id)
    return {"status": "acknowledged", "alert_id": alert_id}


@app.post("/api/alerts/acknowledge-all")
async def acknowledge_all_alerts():
    """Acknowledge all pending alerts."""
    alerts = await db.get_alerts(unacknowledged_only=True)
    for alert in alerts:
        await db.acknowledge_alert(alert["id"])
    return {"status": "ok", "acknowledged": len(alerts)}


# ── Reports ───────────────────────────────────────────────────────────────────

class ActorReportRequest(BaseModel):
    threat_actor: str
    days: int = 30


class SummaryReportRequest(BaseModel):
    days: int = 7


@app.post("/api/reports/actor")
async def generate_actor_report(req: ActorReportRequest):
    """Generate a structured intelligence report for a threat actor."""
    engine = ReportEngine(db)
    report = await engine.generate_actor_report(req.threat_actor, req.days)
    return report


@app.post("/api/reports/summary")
async def generate_summary_report(req: SummaryReportRequest):
    """Generate a weekly threat landscape summary report."""
    engine = ReportEngine(db)
    report = await engine.generate_summary_report(req.days)
    return report


@app.get("/api/reports")
async def list_reports(limit: int = Query(20, le=50)):
    """List all generated reports."""
    reports = await db.get_reports(limit=limit)
    return {"reports": reports, "total": len(reports)}


# ── Sources ───────────────────────────────────────────────────────────────────

@app.get("/api/sources")
async def get_sources():
    """Get connector status and metrics."""
    sources = await db.get_sources()
    job_stats = scheduler.get_job_stats() if scheduler else {}
    for s in sources:
        s["job"] = job_stats.get(s["name"], {})
    return {"sources": sources}


@app.post("/api/sources/{source_name}/refresh")
async def refresh_source(source_name: str):
    """Manually trigger a connector refresh."""
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not running")

    # Map source name to connector class
    from connectors import (
        URLHausConnector, ThreatFoxConnector, FeodoConnector,
        MalwareBazaarConnector, RansomwareLiveConnector, CIRCLOSINTConnector,
        RSSFeedsConnector, FalconFeedsConnector, HIBPConnector, DarkWebConnector
    )
    connector_map = {
        "urlhaus": URLHausConnector,
        "threatfox": ThreatFoxConnector,
        "feodo": FeodoConnector,
        "malwarebazaar": MalwareBazaarConnector,
        "ransomware_live": RansomwareLiveConnector,
        "circl_osint": CIRCLOSINTConnector,
        "rss": RSSFeedsConnector,
        "falconfeeds": FalconFeedsConnector,
        "hibp": HIBPConnector,
        "darkweb": DarkWebConnector,
    }
    cls = connector_map.get(source_name)
    if not cls:
        raise HTTPException(status_code=404, detail=f"Unknown source: {source_name}")

    import asyncio
    asyncio.create_task(scheduler._run_connector(cls, source_name))
    return {"status": "refresh_triggered", "source": source_name}


# ── Logs ──────────────────────────────────────────────────────────────────────

@app.get("/api/logs")
async def get_logs(
    limit: int = Query(200, le=1000),
    level: Optional[str] = None,
):
    """Get platform operation logs."""
    return {"logs": await db.get_logs(limit=limit, level=level)}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "platform": settings.PLATFORM_NAME,
        "version": settings.VERSION,
        "scheduler_running": scheduler.is_running if scheduler else False,
    }
