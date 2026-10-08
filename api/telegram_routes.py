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

from pydantic import BaseModel

class AddChannelRequest(BaseModel):
    handle: str

@router.post("/channel")
async def add_channel(payload: AddChannelRequest):
    """Manually add a Telegram channel to monitor."""
    if not _db:
        raise HTTPException(500, "Database not initialized")
    
    handle = payload.handle.lstrip("@").strip().lower()
    if not handle:
        raise HTTPException(400, "Invalid channel handle")
        
    inserted, is_new = await _db.upsert_telegram_channel({
        "handle": handle,
        "category": "general"
    })
    
    if is_new:
        conn = TelegramMonitorConnector(_db)
        async def check_single():
            metadata = await conn._check_handle_metadata(handle)
            if metadata["status"] == "active":
                category = conn._categorize(metadata["name"] + " " + metadata["description"])
                await _db.upsert_telegram_channel({
                    "handle": handle,
                    "name": metadata["name"],
                    "description": metadata["description"],
                    "subscriber_count": metadata["subscribers"],
                    "category": category
                })
                await _db.update_telegram_status(inserted, "200", metadata["subscribers"])
            else:
                await _db.update_telegram_status(inserted, metadata["status"], 0)
        asyncio.create_task(check_single())
        
        return {"status": "added", "message": f"Channel @{handle} added and status check scheduled."}
    else:
        return {"status": "exists", "message": f"Channel @{handle} is already in the database."}

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
