"""api/social_routes.py — Provides the API endpoints for Social Media Intelligence"""
from fastapi import APIRouter, Query
import logging

router = APIRouter(prefix="/api/social", tags=["social"])
logger = logging.getLogger("api.social")

_db = None

@router.get("/")
async def get_social_intel(
    page: int = 1,
    page_size: int = 50,
    platform: str = None,
    threat_type: str = None
):
    if not _db:
        return {"error": "DB not initialized"}
    
    return await _db.get_social_intel(page, page_size, platform, threat_type)

@router.get("/emerging")
async def get_emerging_threats(limit: int = 20):
    if not _db:
        return {"error": "DB not initialized"}
    
    return await _db.get_social_intel(page=1, page_size=limit, threat_type="emerging")
