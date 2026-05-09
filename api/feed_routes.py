"""
api/feed_routes.py — Live threat intelligence feed endpoints.
Serves the web intel feed (news, blogs, Reddit) to the dashboard.
"""
import logging
from typing import Optional
from fastapi import APIRouter, Query

logger = logging.getLogger("api.feed")
feed_router = APIRouter(prefix="/api/feed", tags=["Live Feed"])
_db = None


@feed_router.get("/latest")
async def get_latest(
    limit:       int            = Query(50, ge=1, le=200),
    category:    Optional[str]  = None,
    hours:       int            = Query(24, ge=1, le=168),
    min_relevance: float        = Query(0.3, ge=0.0, le=1.0),
):
    """Latest threat intel from web sources."""
    items = await _db.get_feed(limit=limit, category=category,
                                hours=hours, min_relevance=min_relevance)
    return {"items": items, "count": len(items)}


@feed_router.get("/search")
async def search_feed(q: str = Query(..., min_length=2), limit: int = Query(20)):
    """Search the threat feed."""
    items = await _db.search_feed(q, limit=limit)
    return {"items": items, "count": len(items), "query": q}


@feed_router.get("/categories")
async def get_categories():
    """Get feed item counts by category."""
    async with _db._conn.execute(
        """SELECT category, COUNT(*) as cnt FROM threat_feed
           WHERE fetched_at >= datetime('now','-24 hours')
           GROUP BY category ORDER BY cnt DESC"""
    ) as cur:
        rows = await cur.fetchall()
    return {"categories": [dict(r) for r in rows]}


@feed_router.get("/stats")
async def feed_stats():
    """Feed statistics."""
    async with _db._conn.execute("SELECT COUNT(*) FROM threat_feed") as cur:
        total = (await cur.fetchone())[0]
    async with _db._conn.execute(
        "SELECT COUNT(*) FROM threat_feed WHERE fetched_at >= datetime('now','-1 hour')"
    ) as cur:
        last_hour = (await cur.fetchone())[0]
    async with _db._conn.execute(
        "SELECT COUNT(*) FROM threat_feed WHERE fetched_at >= datetime('now','-5 minutes')"
    ) as cur:
        last_5min = (await cur.fetchone())[0]
    return {
        "total_items": total,
        "last_hour": last_hour,
        "last_5min": last_5min,
    }
