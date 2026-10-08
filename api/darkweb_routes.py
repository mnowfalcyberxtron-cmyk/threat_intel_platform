"""
api/darkweb_routes.py — Dark web .onion link management API.
Add, edit, delete, test .onion sites without restarting the platform.
Sites are persisted to the database so they survive restarts.
"""

import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("api.darkweb")

dw_router = APIRouter(prefix="/api/darkweb", tags=["Dark Web"])

_db = None
_scheduler = None
_tor_status_task = None


def get_db():        return _db
def get_scheduler(): return _scheduler


async def _ensure_tor_background():
    from config import settings
    from utils.tor_manager import ensure_tor_proxy

    try:
        await ensure_tor_proxy(
            settings.TOR_SOCKS_HOST,
            settings.TOR_SOCKS_PORT,
            allow_start=True,
            timeout=8,
        )
    except Exception as exc:
        logger.warning("Background Tor start failed: %s", exc)


class OnionSite(BaseModel):
    group_name: str
    url: Optional[str] = None  # full .onion URL (optional, will try to resolve)
    description: str = ""
    active: bool = True
    site_type: str = "ransomware"


class OnionSiteUpdate(BaseModel):
    group_name: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    active: Optional[bool] = None
    site_type: Optional[str] = None


# ── Site management ────────────────────────────────────────────────────────────

@dw_router.get("/sites")
async def list_sites():
    """
    List all configured .onion monitoring sites.
    Includes:
    1. config.py defaults
    2. user-added sites from DB (onion_sites table)
    3. DISCOVERED sites gathered from victims table (HIBR/RL data)
    """
    from config import settings
    db = get_db()
    await _ensure_table(db)
    try:
        await db.sync_config_onions()
    except Exception as exc:
        logger.debug("Config onion sync failed while listing sites: %s", exc)

    def normalize_url(url: str) -> str:
        if not url:
            return ""
        url = str(url).strip().lower()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        return url.rstrip("/")

    # Get config defaults
    config_sites = [
        {
            "id": f"config_{i}",
            "group_name": s.get("group") or s.get("group_name") or "Unknown",
            "url": s["url"],
            "description": s.get("description", ""),
            "active": True,
            "source": "config",
        }
        for i, s in enumerate(settings.ONION_SITES)
    ]

    # Get DB sites. Config rows are merged into config_sites below instead
    # of being shown again as user-added rows.
    db_sites = []
    try:
        async with db._conn.execute(
            "SELECT * FROM onion_sites ORDER BY created_at DESC"
        ) as cur:
            rows = await cur.fetchall()
        db_sites = [dict(r) for r in rows]
    except Exception: pass

    # Get DISCOVERED sites from victims
    discovered_sites = await db.get_discovered_onion_sites()
    
    # Deduplicate against config/db sites
    config_url_set = {normalize_url(s["url"]) for s in config_sites}
    known_urls = set(config_url_set)
    known_urls.update({normalize_url(s.get("url")) for s in db_sites})
    
    filtered_discovered = [
        {**s, "id": f"disc_{i}"}
        for i, s in enumerate(discovered_sites)
        if normalize_url(s.get("url")) not in known_urls
    ]

    # Build DB sites map by normalized URL
    db_map = {}
    for s in db_sites:
        u_norm = normalize_url(s.get("url"))
        if u_norm:
            db_map[u_norm] = s

    # Merge DB fields into config sites
    for s in config_sites:
        u_norm = normalize_url(s.get("url"))
        db_row = db_map.get(u_norm)
        if db_row:
            s["screenshot_path"] = db_row.get("screenshot_path") or ""
            s["last_status"] = db_row.get("last_status") or "pending"
            s["last_checked"] = db_row.get("last_checked")
            s["page_title"] = db_row.get("page_title") or ""
            s["full_html"] = db_row.get("full_html") or ""
            s["db_id"] = db_row.get("id")
        else:
            s["screenshot_path"] = ""
            s["last_status"] = "pending"
            s["last_checked"] = None
            s["page_title"] = ""
            s["full_html"] = ""

    # Merge DB fields into discovered sites (just in case they have a status/screenshot tracked in DB)
    for s in filtered_discovered:
        u_norm = normalize_url(s.get("url"))
        db_row = db_map.get(u_norm)
        if db_row:
            s["screenshot_path"] = db_row.get("screenshot_path") or ""
            s["last_status"] = db_row.get("last_status") or "pending"
            s["last_checked"] = db_row.get("last_checked")
            s["page_title"] = db_row.get("page_title") or ""
            s["full_html"] = db_row.get("full_html") or ""
            s["db_id"] = db_row.get("id")
        else:
            s["screenshot_path"] = ""
            s["last_status"] = "pending"
            s["last_checked"] = None
            s["page_title"] = ""
            s["full_html"] = ""

    user_sites = [s for s in db_sites if normalize_url(s.get("url")) not in config_url_set]
    verified_active = sum(
        1 for s in (config_sites + user_sites + filtered_discovered)
        if str(s.get("last_status")) == "200"
    )

    return {
        "config_sites": config_sites,
        "user_sites": user_sites,
        "discovered_sites": filtered_discovered,
        "total": len(config_sites) + len(user_sites) + len(filtered_discovered),
        "active_count": verified_active,
        "tor_required": True,
    }


@dw_router.post("/sites")
async def add_site(site: OnionSite):
    """
    Add a new .onion site to monitor.
    Lenient: allows adding a group even if the URL is not provided 
    (will try to find one from existing intel).
    """
    db = get_db()
    url = (site.url or "").strip()
    
    # If URL is missing, try to resolve from known intel
    if not url or ".onion" not in url:
        discovered_url = await db.get_onion_for_group(site.group_name)
        if discovered_url:
            url = discovered_url
            logger.info(f"Resolved URL for {site.group_name} -> {url}")
        else:
            # Still allow adding if they want to track the group name, 
            # but it won't be scanned without a URL.
            if not url:
                return {"status": "error", "message": f"Could not find a .onion URL for '{site.group_name}'. Please provide one manually."}

    if ".onion" in url and not url.startswith("http"):
        url = f"http://{url}"

    # Ensure table exists before insert
    await _ensure_table(db)

    try:
        # Use upsert: if URL already exists (auto-discovered), update it instead of failing
        cur = await db._conn.execute(
            """INSERT INTO onion_sites (group_name, url, description, active, site_type, created_at, last_checked, last_status)
               VALUES (?, ?, ?, ?, ?, datetime('now'), NULL, 'pending')
               ON CONFLICT(url) DO UPDATE SET
                 group_name = excluded.group_name,
                 description = CASE WHEN excluded.description != '' THEN excluded.description ELSE description END,
                 site_type = CASE WHEN excluded.site_type != '' THEN excluded.site_type ELSE site_type END,
                 active = excluded.active""",
            (site.group_name.strip(), url, site.description.strip(), 1 if site.active else 0, site.site_type)
        )
        await db._conn.commit()
        # Fetch the ID (insert or existing)
        async with db._conn.execute("SELECT id FROM onion_sites WHERE url=?", (url,)) as c2:
            row = await c2.fetchone()
        site_id = row[0] if row else (cur.lastrowid or 0)
        action = "added" if cur.rowcount else "updated"
        await db.log("INFO", "darkweb_manager", f"{action.title()} onion site: {site.group_name} — {url}")

        # Trigger an immediate targeted scan for the new site to get screenshot & metadata
        if site_id:
            from connectors.onion_monitor import OnionMonitorConnector
            from fastapi import BackgroundTasks
            
            async def run_initial_scan(sid):
                connector = OnionMonitorConnector(db)
                await connector.run_targeted_scan(sid)
            
            # We can't easily use BackgroundTasks here without changing function signature, 
            # so we use asyncio.create_task directly as it's already used elsewhere in the project.
            asyncio.create_task(run_initial_scan(site_id))

        return {"status": action, "id": site_id, "group_name": site.group_name, "url": url, "message": "Site added and initial scan triggered."}
    except Exception as e:
        logger.error(f"Failed to add site: {e}")
        raise HTTPException(500, f"Database error: {str(e)}")


@dw_router.put("/sites/{site_id}")
async def update_site(site_id: int, update: OnionSiteUpdate):
    """
    Update an existing user-added .onion site.
    
    Example: Deactivate a site that went offline:
    PUT /api/darkweb/sites/3
    {"active": false}
    
    Example: Update URL when group migrates:
    PUT /api/darkweb/sites/3
    {"url": "http://newurl456xyz.onion"}
    """
    db = get_db()
    await _ensure_table(db)

    async with db._conn.execute("SELECT * FROM onion_sites WHERE id=?", (site_id,)) as cur:
        existing = await cur.fetchone()
    if not existing:
        raise HTTPException(404, f"Site ID {site_id} not found (only user-added sites can be edited)")

    fields = {}
    if update.group_name is not None: fields["group_name"] = update.group_name
    if update.url is not None:
        if ".onion" not in update.url and not update.url.startswith("http"):
            raise HTTPException(400, "URL must be valid")
        fields["url"] = update.url
    if update.description is not None: fields["description"] = update.description
    if update.active is not None: fields["active"] = 1 if update.active else 0
    if update.site_type is not None: fields["site_type"] = update.site_type

    if not fields:
        raise HTTPException(400, "No fields to update")

    set_clause = ", ".join(f"{k}=?" for k in fields)
    values = list(fields.values()) + [site_id]
    await db._conn.execute(f"UPDATE onion_sites SET {set_clause} WHERE id=?", values)
    await db._conn.commit()
    await db.log("INFO", "darkweb_manager", f"Updated onion site ID {site_id}: {fields}")
    return {"status": "updated", "id": site_id, "updated_fields": list(fields.keys())}


@dw_router.delete("/sites/{site_id}")
async def delete_site(site_id: int):
    """
    Delete a user-added .onion site.
    Config.py default sites cannot be deleted (edit config.py directly).
    """
    db = get_db()
    await _ensure_table(db)

    async with db._conn.execute("SELECT group_name, url FROM onion_sites WHERE id=?", (site_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Site not found or is a config default (edit config.py to remove defaults)")

    await db._conn.execute("DELETE FROM onion_sites WHERE id=?", (site_id,))
    await db._conn.commit()
    await db.log("INFO", "darkweb_manager", f"Deleted onion site ID {site_id}: {row['group_name']}")
    return {"status": "deleted", "id": site_id, "group_name": row["group_name"]}


@dw_router.post("/sites/{site_id}/mark-active")
async def mark_site_active(site_id: str):
    """
    Manually mark a .onion site as confirmed-active (HTTP 200).
    Use this when you know a site is live but Tor is not available for automated testing.
    The background monitor will protect sites marked this way against transient timeouts.
    """
    from datetime import datetime, timezone
    db = get_db()
    await _ensure_table(db)

    if str(site_id).startswith("config_"):
        # Config site — update by fetching from config list and updating the DB entry
        from config import settings
        idx = int(site_id.split("_")[1])
        sites_cfg = getattr(settings, "ONION_SITES", [])
        if idx >= len(sites_cfg):
            raise HTTPException(404, f"Config site index {idx} not found")
        site_cfg = sites_cfg[idx]
        group = site_cfg.get("group_name", site_cfg.get("group", "Unknown"))
        url = site_cfg.get("url", "")
        # Insert/update in DB so it's tracked
        try:
            now = datetime.now(timezone.utc).isoformat()
            await db._conn.execute(
                """INSERT INTO onion_sites (group_name, url, description, active, created_at, last_checked, last_status)
                   VALUES (?, ?, ?, 1, ?, ?, '200')
                   ON CONFLICT(url) DO UPDATE SET last_status='200', last_checked=excluded.last_checked""",
                (group, url, "Manually confirmed active", now, now)
            )
            await db._conn.commit()
        except Exception as e:
            raise HTTPException(500, str(e))
        return {"status": "marked_active", "group_name": group, "url": url, "last_status": "200"}

    else:
        # DB site
        try:
            site_int_id = int(site_id)
        except ValueError:
            raise HTTPException(400, f"Invalid site ID: {site_id}")

        async with db._conn.execute("SELECT group_name, url FROM onion_sites WHERE id=?", (site_int_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404, f"Site ID {site_id} not found")

        now = datetime.now(timezone.utc).isoformat()
        await db._conn.execute(
            "UPDATE onion_sites SET last_status='200', last_checked=? WHERE id=?",
            (now, site_int_id)
        )
        await db._conn.commit()
        await db.log("INFO", "darkweb_manager", f"Manually marked active: {row['group_name']} ({row['url']})")
        return {"status": "marked_active", "id": site_int_id, "group_name": row["group_name"], "url": row["url"], "last_status": "200"}


@dw_router.post("/sites/{site_id}/test")
async def test_site(site_id: str):
    """
    Test connectivity to a specific .onion site via Tor.
    Returns response status and latency.
    Works for both config sites (config_N) and user sites (integer ID).
    """
    from config import settings

    # Resolve site URL
    url = None
    group = None
    if str(site_id).startswith("config_"):
        idx = int(site_id.replace("config_", ""))
        if idx < len(settings.ONION_SITES):
            url = settings.ONION_SITES[idx]["url"]
            group = settings.ONION_SITES[idx]["group"]
    elif str(site_id).startswith("disc_"):
        idx = int(site_id.replace("disc_", ""))
        db = get_db()
        discovered = await db.get_discovered_onion_sites()
        if idx < len(discovered):
            url = discovered[idx]["url"]
            group = discovered[idx]["group_name"]
    else:
        db = get_db()
        await _ensure_table(db)
        async with db._conn.execute("SELECT * FROM onion_sites WHERE id=?", (int(site_id),)) as cur:
            row = await cur.fetchone()
        if row:
            url = row["url"]
            group = row["group_name"]

    if not url:
        raise HTTPException(404, "Site not found")

    if not settings.ENABLE_DARKWEB:
        return {
            "status": "skipped",
            "reason": "Dark web monitoring disabled. Set ENABLE_DARKWEB=true in .env",
            "url": url,
        }

    # Test connectivity via Tor
    import time
    try:
        from utils.tor_manager import ensure_tor_proxy
        from aiohttp_socks import ProxyConnector
        import aiohttp, asyncio

        tor = await ensure_tor_proxy(settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT)
        if not tor.get("ok"):
            raise RuntimeError(tor.get("error") or "Tor proxy is not verified")

        proxy = tor["proxy_url"]
        connector = ProxyConnector.from_url(proxy, rdns=True)
        timeout = aiohttp.ClientTimeout(total=30)
        start = time.time()
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            async with sess.get(url, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True, ssl=False) as resp:
                elapsed = round((time.time() - start) * 1000)
                content_len = len(await resp.read())

                if resp.status == 200:
                    # SUCCESS! Upsert the site into DB and trigger background targeted scan for metadata & screenshot
                    db = get_db()
                    db_id = None
                    try:
                        # Normalize URL
                        norm_url = url.strip()
                        if ".onion" in norm_url and not norm_url.startswith("http"):
                            norm_url = f"http://{norm_url}"

                        await db._conn.execute(
                            """INSERT INTO onion_sites (group_name, url, description, active, last_status, last_checked)
                               VALUES (?, ?, 'Auto-tracked Site', 1, '200', datetime('now'))
                               ON CONFLICT(url) DO UPDATE SET last_status='200', last_checked=datetime('now')""",
                            (group.strip(), norm_url)
                        )
                        await db._conn.commit()
                        
                        async with db._conn.execute("SELECT id FROM onion_sites WHERE url=?", (norm_url,)) as c_id:
                            db_row = await c_id.fetchone()
                        if db_row:
                            db_id = db_row[0]
                    except Exception as db_err:
                        logger.error(f"Failed to upsert onion site during test: {db_err}")

                    if db_id:
                        try:
                            from connectors.onion_monitor import OnionMonitorConnector
                            connector_monitor = OnionMonitorConnector(db)
                            asyncio.create_task(connector_monitor.run_targeted_scan(db_id))
                            logger.info(f"Triggered background scrape/screenshot for {group} (ID: {db_id}) after successful test.")
                        except Exception as se:
                            logger.error(f"Failed to trigger screenshot scrape: {se}")

                    return {
                        "status": "reachable",
                        "http_status": 200,
                        "group_name": group,
                        "url": url,
                        "proxy": proxy,
                        "latency_ms": elapsed,
                        "content_bytes": content_len,
                        "message": "Site is online. Triggered full scrape & screenshot.",
                    }
                else:
                    # Not 200 but reachable
                    if not str(site_id).startswith("config_") and not str(site_id).startswith("disc_"):
                        await db._conn.execute(
                            "UPDATE onion_sites SET last_checked=datetime('now'), last_status=? WHERE id=?",
                            (str(resp.status), int(site_id))
                        )
                        await db._conn.commit()
                    
                    return {
                        "status": "error",
                        "http_status": resp.status,
                        "group_name": group,
                        "url": url,
                        "proxy": proxy,
                        "latency_ms": elapsed,
                        "message": f"HTTP {resp.status}",
                    }
    except Exception as e:
        err = str(e)
        if not str(site_id).startswith("config_") and not str(site_id).startswith("disc_"):
            try:
                db = get_db()
                await db._conn.execute(
                    "UPDATE onion_sites SET last_checked=datetime('now'), last_status='error' WHERE id=?",
                    (int(site_id),)
                )
                await db._conn.commit()
            except Exception:
                pass
        return {
            "status": "unreachable",
            "group_name": group,
            "url": url,
            "error": err[:200],
            "message": "Site offline or Tor not running",
            "tor_check": f"Run: curl --socks5-hostname {settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT} https://check.torproject.org/api/ip",
        }


@dw_router.post("/scan/now")
async def trigger_scan():
    """Trigger an immediate dark web scan of all active sites."""
    from config import settings
    if not settings.ENABLE_DARKWEB:
        return {
            "status": "disabled",
            "message": "Set ENABLE_DARKWEB=true in .env and restart to enable dark web monitoring",
        }
    sched = get_scheduler()
    if sched:
        import asyncio
        from connectors.darkweb import DarkWebConnector
        asyncio.create_task(sched._run_connector(DarkWebConnector))
        return {"status": "triggered", "message": "Dark web scan started in background"}
    return {"status": "error", "message": "Scheduler not initialized"}


@dw_router.get("/results")
async def get_darkweb_results(
    group_name: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
):
    """Get victims discovered from dark web monitoring."""
    db = get_db()
    data = await db.get_victims(
        group_name=group_name,
        page=page,
        page_size=page_size,
    )
    # Filter to dark web sourced victims only (source=darkweb or source=haveibeenransom or onion in url)
    items = [v for v in data.get("items", [])
             if v.get("source") in ("darkweb",) or "onion" in str(v.get("source_url",""))]
    # If no dark web specific victims, show all victims (still useful)
    if not items:
        items = data.get("items", [])
    return {
        "total": len(items),
        "page": page,
        "items": items,
        "note": "Showing victims discovered via dark web monitoring",
    }


@dw_router.get("/tor/status")
async def tor_status():
    """Check if Tor is running and reachable."""
    global _tor_status_task
    from config import settings
    try:
        from utils.tor_manager import ensure_tor_proxy, find_tor_binary, is_tor_running

        tor = await ensure_tor_proxy(
            settings.TOR_SOCKS_HOST,
            settings.TOR_SOCKS_PORT,
            allow_start=False,
            timeout=3,
        )
        if tor.get("ok"):
            return {
                "tor_running": True,
                "starting": False,
                "exit_ip": tor.get("exit_ip", "unknown"),
                "proxy": f"{tor.get('host')}:{tor.get('port')}",
                "proxy_url": tor.get("proxy_url"),
                "message": "Tor is working correctly",
            }

        attempts = tor.get("attempts") or []
        open_ports = [
            f"{a.get('host')}:{a.get('port')}"
            for a in attempts
            if a.get("host") and a.get("port") and is_tor_running(a.get("host"), a.get("port"))
        ]

        starting = bool(_tor_status_task and not _tor_status_task.done())
        if not starting and settings.TOR_AUTO_START:
            _tor_status_task = asyncio.create_task(_ensure_tor_background())
            starting = True

        return {
            "tor_running": False,
            "starting": starting,
            "auto_start": bool(settings.TOR_AUTO_START),
            "tor_binary_found": bool(find_tor_binary()),
            "proxy": f"{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}",
            "checked_ports": [f"{a.get('host')}:{a.get('port')}" for a in attempts if a.get("host") and a.get("port")],
            "open_ports": open_ports,
            "error": str(tor.get("error") or "")[:240],
            "message": "Tor is starting in the background." if starting else "No verified Tor proxy found.",
            "install_guide": {
                "windows": "Open Tor Browser, or set TOR_AUTO_START=true so the app can start tor.exe in the background.",
                "verify": f"curl.exe --socks5-hostname {settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT} https://check.torproject.org/api/ip",
            }
        }
    except Exception as e:
        # Fallback to checking if the SOCKS port is open locally
        port_open = False
        try:
            from utils.tor_manager import is_tor_running
            port_open = is_tor_running(settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT)
        except Exception:
            pass

        if port_open:
            return {
                "tor_running": False,
                "exit_ip": "unknown (circuit building)",
                "proxy": f"{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}",
                "message": "A local port is open, but it was not verified as Tor.",
            }

        return {
            "tor_running": False,
            "proxy": f"{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}",
            "error": str(e)[:200],
            "install_guide": {
                "windows": "Open Tor Browser and keep it running. Tor Browser usually listens on 127.0.0.1:9150.",
                "verify": f"curl.exe --socks5-hostname {settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT} https://check.torproject.org/api/ip",
            }
        }

@dw_router.post("/tor/stop")
async def tor_stop():
    """Stop the background Tor process to release file locks."""
    try:
        from utils.tor_manager import stop_tor
        success = stop_tor()
        if success:
            return {"status": "success", "message": "Tor process stopped. You can now modify/delete Tor files."}
        else:
            return {"status": "error", "message": "Could not stop Tor process. See logs for details."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ── DB helper ──────────────────────────────────────────────────────────────────

async def _ensure_table(db):
    """Create onion_sites table if it doesn't exist, with all necessary columns."""
    await db._conn.execute("""
        CREATE TABLE IF NOT EXISTS onion_sites (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name      TEXT NOT NULL,
            url             TEXT NOT NULL UNIQUE,
            description     TEXT DEFAULT '',
            page_title      TEXT DEFAULT '',
            meta_generator  TEXT DEFAULT '',
            full_html       TEXT DEFAULT '',
            last_content    TEXT DEFAULT '',
            screenshot_path TEXT DEFAULT '',
            active          INTEGER DEFAULT 1,
            site_type       TEXT DEFAULT 'ransomware',
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            last_checked    TEXT DEFAULT NULL,
            last_status     TEXT DEFAULT 'pending'
        )
    """)
    # Ensure missing columns exist (migration)
    cols = [
        ("page_title", "TEXT DEFAULT ''"),
        ("meta_generator", "TEXT DEFAULT ''"),
        ("full_html", "TEXT DEFAULT ''"),
        ("last_content", "TEXT DEFAULT ''"),
        ("screenshot_path", "TEXT DEFAULT ''"),
        ("site_type", "TEXT DEFAULT 'ransomware'"),
    ]
    for col, defn in cols:
        try:
            await db._conn.execute(f"ALTER TABLE onion_sites ADD COLUMN {col} {defn}")
        except Exception:
            pass
    await db._conn.commit()
