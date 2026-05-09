"""
api/telegram_routes.py — Provides the API endpoints for Telegram Threat Monitoring
"""
import asyncio
import logging
from fastapi import APIRouter, HTTPException, Query
from connectors.telegram_monitor import TelegramMonitorConnector

router = APIRouter(prefix="/api/telegram", tags=["Telegram Monitor"])
logger = logging.getLogger("api.telegram")

_db = None

@router.get("/channels")
async def get_channels(
    page: int = 1,
    page_size: int = 50,
    category: str = None,
    status: str = None,
    search: str = None
):
    if not _db:
        raise HTTPException(500, "Database not initialized")
    return await _db.get_telegram_channels(page, page_size, category, status, search)

@router.post("/refresh")
async def refresh_telegram():
    """Trigger background Telegram discovery and status check."""
    if not _db:
        raise HTTPException(500, "Database not initialized")
    
    conn = TelegramMonitorConnector(_db)
    asyncio.create_task(conn.run())
    return {"status": "triggered", "message": "Telegram monitoring cycle started in background"}

@router.get("/stats")
async def get_stats():
    if not _db:
        raise HTTPException(500, "Database not initialized")
    
    async with _db._conn.execute("SELECT COUNT(*) FROM telegram_channels") as cur:
        total = (await cur.fetchone())[0]
    async with _db._conn.execute("SELECT COUNT(*) FROM telegram_channels WHERE last_status='200'") as cur:
        active = (await cur.fetchone())[0]
    async with _db._conn.execute("SELECT category, COUNT(*) as count FROM telegram_channels GROUP BY category") as cur:
        categories = [dict(r) for r in await cur.fetchall()]
    
    return {
        "total_channels": total,
        "active_channels": active,
        "categories": categories
    }
