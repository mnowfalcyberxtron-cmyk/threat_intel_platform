"""
api/hibr_routes.py — HaveIBeenRansom investigation endpoints.
These are NOT scheduled — they're on-demand search/investigation tools.

All results stored locally. No external redirects in the UI.
"""

import json
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

    # Optionally trigger AI analysis if results found
    ai = get_ai()
    ai_summary = None
    results = data.get("data", [])
    if results and ai:
        try:
            hits = data.get("total_hits", len(results))
            prompt = (
                f"HIBR breach data search results for '{query}' (field: {fields}):\n"
                f"Total hits: {hits}\n"
                f"Sample records ({min(len(results),5)}):\n"
                + json.dumps(results[:5], indent=2, default=str)
                + "\n\nProvide a brief intelligence assessment: what does this exposure mean, "
                  "what data types are compromised, what are the risks?"
            )
            ai_summary = await ai.chat(prompt)
        except Exception as e:
            logger.debug("AI summary failed: %s", e)

    return {**data, "ai_summary": ai_summary}


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

@hibr_router.get("/investigate/domain/{domain}")
async def investigate_domain(domain: str):
    """
    Full domain investigation: metadata + fulldata + fullstealer + AI analysis.
    One endpoint for complete breach picture of a target domain.
    
    Example: GET /api/hibr/investigate/domain/targetcorp.com
    """
    hibr = get_hibr()
    if not _check():
        raise HTTPException(503, detail=_config_help())

    # Run all three searches concurrently
    import asyncio
    meta_task     = hibr.search_metadata("domain", domain)
    fulldata_task = hibr.search_fulldata("domain", domain)
    stealer_task  = hibr.search_fullstealer("domain", domain)

    meta, fulldata, stealer = await asyncio.gather(
        meta_task, fulldata_task, stealer_task, return_exceptions=True
    )

    # Handle exceptions gracefully
    if isinstance(meta, Exception):     meta = None
    if isinstance(fulldata, Exception): fulldata = None
    if isinstance(stealer, Exception):  stealer = None

    return {
        "domain": domain,
        "metadata": meta,
        "fulldata_summary": {
            "total_hits": (fulldata or {}).get("total_hits", 0),
            "sample": (fulldata or {}).get("data", [])[:5],
            "has_more": (fulldata or {}).get("has_next_page", False),
        },
        "stealer_summary": {
            "total_hits": (stealer or {}).get("total_hits", 0),
            "sample": (stealer or {}).get("data", [])[:5],
            "has_more": (stealer or {}).get("has_next_page", False),
        },
        "ai_analysis": None,
    }


@hibr_router.get("/investigate/email/{email}")
async def investigate_email(email: str):
    """
    Full email investigation: fulldata + fullstealer + AI analysis.
    
    Example: GET /api/hibr/investigate/email/user@corp.com
    """
    hibr = get_hibr()
    if not _check():
        raise HTTPException(503, detail=_config_help())

    import asyncio
    fulldata_task = hibr.search_fulldata("email", email)
    stealer_task  = hibr.search_fullstealer("email", email)
    fulldata, stealer = await asyncio.gather(fulldata_task, stealer_task, return_exceptions=True)
    if isinstance(fulldata, Exception): fulldata = None
    if isinstance(stealer, Exception):  stealer = None

    return {
        "email": email,
        "fulldata": {
            "total_hits": (fulldata or {}).get("total_hits", 0),
            "records": (fulldata or {}).get("data", []),
            "has_more": (fulldata or {}).get("has_next_page", False),
        },
        "stealer": {
            "total_hits": (stealer or {}).get("total_hits", 0),
            "records": (stealer or {}).get("data", []),
            "has_more": (stealer or {}).get("has_next_page", False),
        },
        "ai_analysis": None,
    }


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
