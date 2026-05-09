"""api/onion_routes.py — Provides the API endpoints for the Onion Monitor UI"""
from fastapi import APIRouter, BackgroundTasks
import logging

router = APIRouter(prefix="/api/onion", tags=["onion"])
logger = logging.getLogger("api.onion")

_db = None
_scheduler = None
_monitor_connector = None

@router.get("/status")
async def get_onion_statuses():
    if not _db:
        return {"error": "DB not initialized"}
        
    async with _db._conn.execute("SELECT id, group_name, url, last_checked, last_status, description, screenshot_path, full_html FROM onion_sites ORDER BY group_name ASC") as cur:
        rows = await cur.fetchall()
        
    online = []
    offline = []
    pending = []
    
    for r in rows:
        d = dict(r)
        st = str(d.get("last_status", "pending"))
        if st == "200":
            online.append(d)
        elif st == "pending" or st == "None":
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
            "pending": len(pending)
        },
        "online_sites": online,
        "offline_sites": offline,
        "recent_changes": changes
    }

@router.post("/scan")
async def trigger_onion_scan(background_tasks: BackgroundTasks):
    from connectors.onion_monitor import OnionMonitorConnector
    if not _db: return {"status": "error"}
    
    async def run_scan():
        connector = OnionMonitorConnector(_db)
        await connector.run(pending_only=False)
        
    background_tasks.add_task(run_scan)
    return {"status": "scan_started", "message": "Onion monitor scan started in background"}

@router.post("/scan-pending")
async def trigger_onion_scan_pending(background_tasks: BackgroundTasks):
    from connectors.onion_monitor import OnionMonitorConnector
    if not _db: return {"status": "error"}
    
    async def run_scan():
        connector = OnionMonitorConnector(_db)
        await connector.run(pending_only=True)
        
    background_tasks.add_task(run_scan)
    return {"status": "scan_started", "message": "Pending-only onion scan started in background"}

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
