"""
api/feed_routes.py — Live threat intelligence feed endpoints.
Serves the web intel feed (news, blogs, Reddit) to the dashboard.
"""
import logging
import time
from typing import Optional
from fastapi import APIRouter, Query

logger = logging.getLogger("api.feed")
feed_router = APIRouter(prefix="/api/feed", tags=["Live Feed"])
_db = None

# In-memory caches with 15-second TTL
_stats_cache = None
_stats_cache_ts = 0

_latest_cache = {}  # key -> (items, timestamp)
_CACHE_TTL = 15.0


@feed_router.get("/latest")
async def get_latest(
    limit:       int            = Query(50, ge=1, le=200),
    category:    Optional[str]  = None,
    hours:       str            = Query("24"),
    min_relevance: float        = Query(0.3, ge=0.0, le=1.0),
):
    """Latest threat intel from web sources."""
    global _latest_cache
    now = time.time()
    
    # Clean up expired cache items
    _latest_cache = {k: v for k, v in _latest_cache.items() if now - v[1] < _CACHE_TTL}
    
    cache_key = f"{limit}:{category}:{hours}:{min_relevance}"
    if cache_key in _latest_cache:
        cached_items, cached_ts = _latest_cache[cache_key]
        return {"items": cached_items, "count": len(cached_items), "cached": True}
        
    val = hours
    if val != "today":
        try:
            val = int(hours)
        except ValueError:
            val = 24
    items = await _db.get_feed(limit=limit, category=category,
                                hours=val, min_relevance=min_relevance)
                                
    _latest_cache[cache_key] = (items, now)
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
    global _stats_cache, _stats_cache_ts
    now = time.time()
    
    if _stats_cache and (now - _stats_cache_ts < _CACHE_TTL):
        return {**_stats_cache, "cached": True}
        
    # Combined single query to fetch all counts in one scan
    async with _db._conn.execute("""
        SELECT 
            COUNT(*),
            SUM(CASE WHEN fetched_at >= datetime('now','-1 hour') THEN 1 ELSE 0 END),
            SUM(CASE WHEN fetched_at >= datetime('now','-5 minutes') THEN 1 ELSE 0 END)
        FROM threat_feed
    """) as cur:
        row = await cur.fetchone()
        
    total = row[0] or 0
    last_hour = row[1] or 0
    last_5min = row[2] or 0
    
    _stats_cache = {
        "total_items": total,
        "last_hour": last_hour,
        "last_5min": last_5min,
    }
    _stats_cache_ts = now
    
    return _stats_cache

