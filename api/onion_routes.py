"""api/onion_routes.py — Provides the API endpoints for the Onion Monitor UI"""
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks
import logging

router = APIRouter(prefix="/api/onion", tags=["onion"])
logger = logging.getLogger("api.onion")

_db = None
_scheduler = None
_monitor_connector = None
_scan_task = None
_scan_mode = ""
_scan_started_at = ""
_scan_finished_at = ""
_scan_error = ""

@router.get("/status")
async def get_onion_statuses():
    if not _db:
        return {"error": "DB not initialized"}

    try:
        await _db.sync_discovered_onions()
    except Exception as exc:
        logger.debug("Onion status pre-sync failed: %s", exc)
        
    try:
        async with _db._conn.execute(
            """SELECT id, group_name, url, last_checked, last_status, description,
                      page_title, screenshot_path,
                      LENGTH(COALESCE(full_html,'')) AS html_size
               FROM onion_sites
               ORDER BY group_name ASC"""
        ) as cur:
            rows = await cur.fetchall()
    except Exception as exc:
        logger.error("Onion status query failed: %s", exc)
        return {
            "summary": {"total": 0, "online": 0, "offline": 0, "pending": 0},
            "online_sites": [],
            "offline_sites": [],
            "pending_sites": [],
            "recent_changes": [],
            "error": str(exc),
        }
        
    online = []
    offline = []
    pending = []
    last_checked_values = []
    
    for r in rows:
        d = dict(r)
        st = str(d.get("last_status") or "pending")
        if d.get("last_checked"):
            last_checked_values.append(d["last_checked"])
        if st == "200":
            online.append(d)
        elif st.lower() in ("pending", "none", ""):
            pending.append(d)
        else:
            offline.append(d)
            
    # Recent changes can be extracted from alerts
    async with _db._conn.execute(
        "SELECT title, description, created_at FROM alerts WHERE alert_type='onion_status_change' ORDER BY created_at DESC LIMIT 10"
    ) as cur:
        changes = [dict(c) for c in await cur.fetchall()]

    return {
        "summary": {
            "total": len(rows),
            "online": len(online),
            "offline": len(offline),
            "pending": len(pending),
            "last_checked": max(last_checked_values) if last_checked_values else ""
        },
        "scan": {
            "running": bool(_scan_task and not _scan_task.done()),
            "mode": _scan_mode,
            "started_at": _scan_started_at,
            "finished_at": _scan_finished_at,
            "error": _scan_error,
        },
        "online_sites": online,
        "offline_sites": offline,
        "pending_sites": pending,
        "recent_changes": changes
    }

async def _run_scan(mode: str, pending_only: bool):
    global _scan_task, _scan_mode, _scan_started_at, _scan_finished_at, _scan_error

    from connectors.onion_monitor import OnionMonitorConnector

    _scan_mode = mode
    _scan_started_at = datetime.now(timezone.utc).isoformat()
    _scan_finished_at = ""
    _scan_error = ""
    _scan_task = asyncio.current_task()

    try:
        connector = OnionMonitorConnector(_db)
        await connector.run(pending_only=pending_only)
    except Exception as exc:
        _scan_error = str(exc)
        logger.exception("Onion monitor %s scan failed: %s", mode, exc)
    finally:
        _scan_finished_at = datetime.now(timezone.utc).isoformat()
        _scan_mode = ""
        _scan_task = None


def _scan_payload(status: str, message: str) -> dict:
    return {
        "status": status,
        "message": message,
        "scan": {
            "running": bool(_scan_task and not _scan_task.done()),
            "mode": _scan_mode,
            "started_at": _scan_started_at,
            "finished_at": _scan_finished_at,
            "error": _scan_error,
        },
    }


@router.post("/scan")
async def trigger_onion_scan(background_tasks: BackgroundTasks):
    global _scan_task, _scan_mode, _scan_started_at, _scan_finished_at, _scan_error

    if not _db:
        return {"status": "error", "message": "DB not initialized"}
    if _scan_task and not _scan_task.done():
        return _scan_payload("already_running", "Onion monitor scan is already running")

    _scan_mode = "all"
    _scan_started_at = datetime.now(timezone.utc).isoformat()
    _scan_finished_at = ""
    _scan_error = ""
    _scan_task = asyncio.create_task(_run_scan("all", pending_only=False))
    return _scan_payload("scan_started", "Onion monitor scan started in background")

@router.post("/scan-pending")
async def trigger_onion_scan_pending(background_tasks: BackgroundTasks):
    global _scan_task, _scan_mode, _scan_started_at, _scan_finished_at, _scan_error

    if not _db:
        return {"status": "error", "message": "DB not initialized"}
    if _scan_task and not _scan_task.done():
        return _scan_payload("already_running", "Onion monitor scan is already running")

    _scan_mode = "pending"
    _scan_started_at = datetime.now(timezone.utc).isoformat()
    _scan_finished_at = ""
    _scan_error = ""
    _scan_task = asyncio.create_task(_run_scan("pending", pending_only=True))
    return _scan_payload("scan_started", "Pending-only onion scan started in background")

@router.post("/victim/{victim_id}/snapshot")
async def capture_victim_snapshot(victim_id: int, background_tasks: BackgroundTasks):
    """Trigger a targeted screenshot for a specific victim's site."""
    if not _db: return {"status": "error"}
    
    # 1. Look up victim to get site_id and name
    async with _db._conn.execute(
        "SELECT id, victim_name, onion_url FROM ransomware_victims WHERE id=?", (victim_id,)
    ) as cur:
        vic = await cur.fetchone()
    
    if not vic:
        return {"success": False, "error": "Victim not found"}
    
    v_id, v_name, v_url = vic
    
    # 2. Look up onion_site by URL (simple match)
    async with _db._conn.execute(
        "SELECT id FROM onion_sites WHERE url LIKE ?", (f"%{v_url}%",)
    ) as cur:
        site = await cur.fetchone()
    
    if not site:
        return {"success": False, "error": "Onion site not found for this victim"}
    
    site_id = site[0]
    
    async def run_targeted():
        from connectors.onion_monitor import OnionMonitorConnector
        connector = OnionMonitorConnector(_db)
        await connector.run_targeted_scan(site_id, victim_name=v_name)
    
    background_tasks.add_task(run_targeted)
    return {"success": True, "message": f"Targeted snapshot for {v_name} started in background"}
