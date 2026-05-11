"""
api/breach_routes.py — Breach Market intelligence from RansomLook.io
Provides endpoints for the Breach Market dashboard section.
"""
import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException

logger = logging.getLogger("api.breach")

breach_router = APIRouter(prefix="/api/breach", tags=["Breach Market"])

_db = None
_scheduler = None

def get_db():        return _db
def get_scheduler(): return _scheduler


# ── Ensure breach_markets table ───────────────────────────────────────────────

async def _ensure_table(db):
    """Create breach_markets table if missing."""
    await db._conn.execute("""
        CREATE TABLE IF NOT EXISTS breach_markets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            url         TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            site_type   TEXT DEFAULT 'market',
            source      TEXT DEFAULT 'ransomlook',
            active      INTEGER DEFAULT 1,
            last_status TEXT DEFAULT 'pending',
            last_checked TEXT DEFAULT NULL,
            screenshot_path TEXT DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # Add missing columns for older installs
    for col, defn in [
        ("screenshot_path", "TEXT DEFAULT ''"),
        ("source", "TEXT DEFAULT 'ransomlook'"),
        ("description", "TEXT DEFAULT ''"),
    ]:
        try:
            await db._conn.execute(f"ALTER TABLE breach_markets ADD COLUMN {col} {defn}")
        except Exception:
            pass
    await db._conn.commit()


# ── Routes ─────────────────────────────────────────────────────────────────────

@breach_router.get("/markets")
async def list_markets(
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
):
    """
    List all tracked breach markets.
    Optionally filter by status (online/offline/pending) or search by name/url.
    """
    db = get_db()
    await _ensure_table(db)

    where_clauses = []
    params = []

    if status:
        if status == "online":
            where_clauses.append("last_status = '200'")
        elif status == "offline":
            where_clauses.append("last_status NOT IN ('200', 'pending') AND last_status IS NOT NULL")
        elif status == "pending":
            where_clauses.append("last_status = 'pending' OR last_status IS NULL")

    if search:
        where_clauses.append("(LOWER(name) LIKE ? OR LOWER(url) LIKE ?)")
        params.extend([f"%{search.lower()}%", f"%{search.lower()}%"])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    offset = (page - 1) * page_size

    async with db._conn.execute(
        f"SELECT COUNT(*) as cnt FROM breach_markets {where_sql}", params
    ) as cur:
        total = (await cur.fetchone())["cnt"]

    async with db._conn.execute(
        f"""SELECT * FROM breach_markets {where_sql}
            ORDER BY
              CASE WHEN last_status='200' THEN 0 ELSE 1 END,
              updated_at DESC
            LIMIT ? OFFSET ?""",
        params + [page_size, offset],
    ) as cur:
        rows = await cur.fetchall()

    items = [dict(r) for r in rows]

    # Compute stats
    all_rows = items if not where_clauses else None
    if all_rows is None:
        async with db._conn.execute(
            "SELECT last_status, COUNT(*) as cnt FROM breach_markets GROUP BY last_status"
        ) as cur:
            status_rows = await cur.fetchall()
        status_counts = {r["last_status"]: r["cnt"] for r in status_rows}
    else:
        from collections import Counter
        status_counts = dict(Counter(r["last_status"] for r in items))

    online  = status_counts.get("200", 0)
    pending = sum(v for k, v in status_counts.items() if k in ("pending", None, ""))
    offline = total - online - pending

    return {
        "total": total,
        "online": online,
        "offline": offline,
        "pending": pending,
        "page": page,
        "page_size": page_size,
        "items": items,
    }


@breach_router.post("/markets/refresh")
async def refresh_markets():
    """
    Trigger a background refresh of breach market URLs from RansomLook.io.
    Scrapes the /urls.csv endpoint and upserts all market entries.
    """
    db = get_db()
    await _ensure_table(db)
    asyncio.create_task(_do_refresh(db))
    return {"status": "triggered", "message": "Background refresh started from ransomlook.io"}


async def _do_refresh(db):
    """Background task: use RansomlookMarketConnector to sync markets."""
    from connectors.ransomlook_market import RansomlookMarketConnector
    logger.info("Triggering breach market refresh via connector...")
    try:
        conn = RansomlookMarketConnector(db=db)
        # We only want to refresh markets here, fetch() does both markets and victims.
        # But RansomlookMarketConnector.fetch() calls _refresh_breach_markets() internally.
        # To be precise, we call the internal helper or just fetch() and ignore victims
        # because the scheduler handles victims.
        await conn._ensure_breach_table()
        await conn._refresh_breach_markets()
        logger.info("Sync complete. Triggering uptime & screenshot check for all markets...")
        await conn.check_all_markets()
        logger.info("Breach market refresh + checks complete.")
    except Exception as e:
        logger.error("Breach market refresh failed: %s", e)
        await db.log("ERROR", "breach_market", f"Refresh failed: {e}")



@breach_router.post("/markets/{market_id}/check")
async def check_market_status(market_id: int):
    """
    Check the live HTTP status of a single breach market URL.
    Updates last_status in DB.
    """
    db = get_db()
    await _ensure_table(db)

    async with db._conn.execute("SELECT * FROM breach_markets WHERE id=?", (market_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Market not found")

    url = row["url"]
    from connectors.ransomlook_market import RansomlookMarketConnector
    conn = RansomlookMarketConnector(db)
    status_code, error_msg = await conn._check_url_robust(url)

    await db._conn.execute(
        "UPDATE breach_markets SET last_status=?, last_checked=datetime('now'), updated_at=datetime('now') WHERE id=?",
        (str(status_code) if status_code else f"error:{error_msg[:40]}", market_id),
    )
    await db._conn.commit()

    return {
        "id": market_id,
        "name": row["name"],
        "url": url,
        "status_code": status_code,
        "online": status_code == 200,
        "error": error_msg,
    }


@breach_router.post("/markets/check-all")
async def check_all_markets():
    """
    Trigger background uptime check of ALL breach market URLs.
    """
    db = get_db()
    await _ensure_table(db)
    asyncio.create_task(_check_all_background(db))
    return {"status": "triggered", "message": "Background uptime check started for all markets"}


async def _check_all_background(db):
    """Check all breach market URLs concurrently via the connector."""
    from connectors.ransomlook_market import RansomlookMarketConnector
    conn = RansomlookMarketConnector(db)
    await conn.check_all_markets()




@breach_router.get("/markets/stats")
async def market_stats():
    """Quick stats: total, online, offline, pending counts."""
    db = get_db()
    await _ensure_table(db)

    async with db._conn.execute(
        "SELECT last_status, COUNT(*) as cnt FROM breach_markets GROUP BY last_status"
    ) as cur:
        rows = await cur.fetchall()

    async with db._conn.execute("SELECT COUNT(*) as cnt FROM breach_markets") as cur:
        total = (await cur.fetchone())["cnt"]

    online  = sum(r["cnt"] for r in rows if r["last_status"] == "200")
    pending = sum(r["cnt"] for r in rows if r["last_status"] in ("pending", None, ""))
    offline = total - online - pending

    async with db._conn.execute(
        "SELECT MAX(last_checked) as lc FROM breach_markets WHERE last_checked IS NOT NULL"
    ) as cur:
        last_check = (await cur.fetchone())["lc"]

    return {
        "total": total,
        "online": online,
        "offline": offline,
        "pending": pending,
        "last_checked": last_check,
    }


@breach_router.delete("/markets/{market_id}")
async def delete_market(market_id: int):
    """Remove a breach market entry."""
    db = get_db()
    await _ensure_table(db)
    async with db._conn.execute("SELECT name FROM breach_markets WHERE id=?", (market_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Market not found")
    await db._conn.execute("DELETE FROM breach_markets WHERE id=?", (market_id,))
    await db._conn.commit()
    return {"status": "deleted", "id": market_id, "name": row["name"]}
