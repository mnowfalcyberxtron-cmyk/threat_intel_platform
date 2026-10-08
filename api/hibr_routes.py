"""
api/hibr_routes.py — HaveIBeenRansom investigation endpoints.
These are NOT scheduled — they're on-demand search/investigation tools.

All results stored locally. No external redirects in the UI.
"""

import json
import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger("api.hibr")

hibr_router = APIRouter(prefix="/api/hibr", tags=["HIBR Investigation"])

_db  = None
_ai  = None
_hibr = None   # HIBRConnector instance (injected from main.py)

def get_db():   return _db
def get_ai():   return _ai
def get_hibr(): return _hibr


# ── Status ─────────────────────────────────────────────────────────────────────

@hibr_router.get("/status")
async def hibr_status():
    """Check HIBR API configuration and total breach count."""
    from config import settings
    configured = bool(settings.HIBR_API_KEY and settings.ENABLE_HIBR)
    result = {
        "configured": configured,
        "enabled": settings.ENABLE_HIBR,
        "api_key_set": bool(settings.HIBR_API_KEY),
        "setup_guide": {
            "step1": "Add HIBR_API_KEY=your_key to .env",
            "step2": "Add ENABLE_HIBR=true to .env",
            "step3": "Add HIBR_INTERVAL=3600 to .env (optional)",
            "step4": "Restart: python main.py",
            "api_docs": "https://haveibeenransom.com/api/",
        }
    }
    if configured:
        hibr = get_hibr()
        total = await hibr.get_total_breaches()
        result["total_breaches_in_hibr"] = total
    return result


# ── Breach list ─────────────────────────────────────────────────────────────────

@hibr_router.get("/breaches/total")
async def get_total():
    """Total breach count in HIBR database."""
    hibr = get_hibr()
    if not _check():
        raise HTTPException(503, "HIBR not configured — add HIBR_API_KEY to .env")
    total = await hibr.get_total_breaches()
    return {"total": total}


# ── Metadata search ─────────────────────────────────────────────────────────────

@hibr_router.get("/search/metadata/{field}/{query}")
async def metadata_search(
    field: str,
    query: str,
    page: int = Query(1, ge=1),
):
    """
    Search HIBR metadata (breach summary, no sensitive data).
    
    field: name | phone | email | username | id | country | domain | password
    query: search term (e.g., domain: targetcorp.com)
    
    Example: GET /api/hibr/search/metadata/domain/targetcorp.com
    """
    hibr = get_hibr()
    if not _check():
        raise HTTPException(503, detail=_config_help())
    data = await hibr.search_metadata(field, query, page)
    if not data:
        raise HTTPException(504, "HIBR API unavailable or query failed")
    return data


# ── Full data search ────────────────────────────────────────────────────────────

@hibr_router.get("/search/fulldata/{fields}/{query}")
async def fulldata_search(
    fields: str,
    query: str,
    search_after: int = Query(0, ge=0),
):
    """
    Search HIBR full breach data (detailed records).
    
    fields: email | phone | domain | id | country | name | username | password
            Multi-field: email,username
    query: search term
    search_after: pagination offset (use value from previous response)
    
    Example: GET /api/hibr/search/fulldata/domain/targetcorp.com
    Example: GET /api/hibr/search/fulldata/email/user@corp.com
    """
    hibr = get_hibr()
    if not _check():
        raise HTTPException(503, detail=_config_help())
    data = await hibr.search_fulldata(fields, query, search_after)
    if not data:
        raise HTTPException(504, "HIBR API unavailable")

    return data



# ── Fullstealer search ──────────────────────────────────────────────────────────

@hibr_router.get("/search/fullstealer/{fields}/{term}")
async def fullstealer_search(
    fields: str,
    term: str,
    search_after: int = Query(0, ge=0),
):
    """
    Search HIBR infostealer logs (credentials, wallets, Steam, Telegram, HWID, etc).
    
    fields: email | name | phone | username | id | country | domain | password |
            wallets | steamid | steamuser | teleid | teleuser | telephone |
            telelink | vpn | ftp | hwid
    term: search term
    
    Example: GET /api/hibr/search/fullstealer/domain/targetcorp.com
    Example: GET /api/hibr/search/fullstealer/email/user@corp.com
    Example: GET /api/hibr/search/fullstealer/hwid/HWID-ABC-123
    """
    hibr = get_hibr()
    if not _check():
        raise HTTPException(503, detail=_config_help())
    data = await hibr.search_fullstealer(fields, term, search_after)
    if not data:
        raise HTTPException(504, "HIBR API unavailable")
    return data


# ── Combined investigation ──────────────────────────────────────────────────────

async def _run_investigation(target: str, target_type: str, refresh: bool) -> dict:
    db = get_db()

    # 1. Check Cache — serve immediately if cached and not forcing refresh
    old_data = None
    if db:
        old_data = await db.get_hibr_search(target, target_type)
        if old_data and not refresh:
            logger.info("HIBR cache hit for %s (%s)", target, target_type)
            return old_data

    # 2. Run API Investigation with a global timeout to prevent infinite hang
    hibr = get_hibr()
    from engine.hibr_search import HIBRSecuritySearchEngine
    engine = HIBRSecuritySearchEngine(hibr, max_depth=2, request_budget=30, concurrency=3)
    try:
        results = await asyncio.wait_for(engine.run(target, target_type), timeout=120.0)
    except asyncio.TimeoutError:
        logger.warning("HIBR investigation timed out after 120s — returning partial results")
        # Build partial results from whatever was collected so far
        from engine.hibr_search import HIBRSecuritySearchEngine
        results = {
            "start_entity": {"value": target, "type": target_type},
            "stats": {
                "depth_reached": 0,
                "api_calls_made": engine.requests_made,
                "entities_discovered": len(engine.visited_entities),
                "metadata_count": len(engine.all_metadata),
                "fulldata_count": len(engine.all_fulldata),
                "fullstealer_count": len(engine.all_fullstealer),
                "partial": True,
            },
            "metadata":    engine.deduplicate_metadata(engine.all_metadata),
            "fulldata":    engine.deduplicate_fulldata(engine.all_fulldata),
            "fullstealer": engine.deduplicate_fullstealer(engine.all_fullstealer),
            "graph": {"nodes": list(engine.nodes.values()), "edges": engine.edges},
            "timeline": {"json": {}, "ascii": "[timed out — partial results]"},
        }

    # 3. Diff old vs new records
    if old_data:
        old_meta  = {str(r.get("id", "")): r for r in old_data.get("metadata", [])}
        old_full  = {f"{(r.get('full_data') or r).get('email','')}{(r.get('full_data') or r).get('domain','')}{(r.get('full_data') or r).get('id_source','')}": r
                     for r in old_data.get("fulldata", [])}
        old_steal = {str(hash(json.dumps({k: v for k, v in r.items() if k != "is_new"}, sort_keys=True))): r
                     for r in old_data.get("fullstealer", [])}

        for r in results.get("metadata", []):
            if str(r.get("id", "")) not in old_meta:
                r["is_new"] = True

        for r in results.get("fulldata", []):
            fd = r.get("full_data") or r
            k  = f"{fd.get('email','')}{fd.get('domain','')}{fd.get('id_source','')}"
            if k not in old_full:
                r["is_new"] = True

        for r in results.get("fullstealer", []):
            k = str(hash(json.dumps({kk: v for kk, v in r.items() if kk != "is_new"}, sort_keys=True)))
            if k not in old_steal:
                r["is_new"] = True

    # 4. Save to DB
    if db:
        await db.save_hibr_search(target, target_type, json.dumps(results))
        results["_cached_at"] = None  # Just ran

    return results

@hibr_router.get("/investigate/domain/{domain}")
async def investigate_domain(domain: str, refresh: bool = False):
    """
    Full domain investigation: metadata + fulldata + fullstealer + recursive entity expansion.
    """
    if not _check():
        raise HTTPException(503, detail=_config_help())
    return await _run_investigation(domain, "domain", refresh)

@hibr_router.get("/investigate/email/{email}")
async def investigate_email(email: str, refresh: bool = False):
    """
    Full email investigation: metadata + fulldata + fullstealer + recursive entity expansion.
    """
    if not _check():
        raise HTTPException(503, detail=_config_help())
    return await _run_investigation(email, "email", refresh)


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _check() -> bool:
    from config import settings
    return bool(settings.HIBR_API_KEY and settings.ENABLE_HIBR)


def _config_help() -> str:
    return (
        "HIBR not configured. Add to your .env file:\n"
        "  HIBR_API_KEY=your_key_here\n"
        "  ENABLE_HIBR=true\n"
        "Then restart: python main.py\n"
        "Get API key: https://haveibeenransom.com/"
    )
