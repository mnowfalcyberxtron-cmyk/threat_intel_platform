"""
api/ai_routes.py — AI analysis endpoints for CyberXTron TIP v2
All analysis is done locally via configured AI provider — no external redirects.
"""

import json
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("api.ai")

ai_router = APIRouter(prefix="/api/ai", tags=["AI Analysis"])

_db = None
_ai = None


def get_db(): return _db
def get_ai(): return _ai


class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None


class AdvisoryRequest(BaseModel):
    days: int = 7
    title: Optional[str] = None


class ActorRequest(BaseModel):
    actor_name: str


class ProviderSelectRequest(BaseModel):
    provider: str


@ai_router.get("/analyze/ioc/{ioc_id}")
async def analyze_ioc(ioc_id: int):
    """AI-powered deep analysis of a specific IOC."""
    db = get_db()
    ai = get_ai()
    ioc = await db.get_ioc_by_id(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    for field in ("sources", "tags", "raw_data"):
        if isinstance(ioc.get(field), str):
            try: ioc[field] = json.loads(ioc[field])
            except: ioc[field] = []
    analysis = await ai.analyze_ioc(ioc)
    return {"ioc_id": ioc_id, "ioc": ioc, "analysis": analysis}


@ai_router.get("/analyze/actor/{actor_name}")
async def analyze_actor(actor_name: str):
    """AI-powered threat actor profile."""
    db = get_db()
    ai = get_ai()
    iocs_data = await db.get_iocs(threat_actor=actor_name, page_size=200)
    victims_data = await db.get_victims(group_name=actor_name, page_size=100)
    iocs = iocs_data.get("items", [])
    victims = victims_data.get("items", [])
    analysis = await ai.analyze_threat_actor(actor_name, iocs, victims)
    return {
        "actor": actor_name,
        "ioc_count": len(iocs),
        "victim_count": len(victims),
        "analysis": analysis,
    }


@ai_router.get("/analyze/group/{group_name}")
async def analyze_ransomware_group(group_name: str):
    """AI-powered ransomware group intelligence."""
    db = get_db()
    ai = get_ai()
    victims_data = await db.get_victims(group_name=group_name, page_size=200)
    victims = victims_data.get("items", [])
    analysis = await ai.analyze_ransomware_group(group_name, victims)
    return {"group": group_name, "victim_count": len(victims), "analysis": analysis}


@ai_router.get("/analyze/victim/{victim_id}")
async def analyze_victim(victim_id: int):
    """AI analysis of a dark web leak/victim posting."""
    db = get_db()
    ai = get_ai()
    async with db._conn.execute("SELECT * FROM ransomware_victims WHERE id=?", (victim_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Victim not found")
    victim = dict(row)
    analysis = await ai.analyze_darkweb_leak(victim)
    return {"victim_id": victim_id, "victim": victim, "analysis": analysis}


@ai_router.post("/advisory")
async def generate_advisory(req: AdvisoryRequest):
    """Generate full AI-written threat intelligence advisory."""
    db = get_db()
    ai = get_ai()
    stats = await db.get_stats()
    from datetime import datetime, timezone, timedelta
    date_from = (datetime.now(timezone.utc) - timedelta(days=req.days)).isoformat()
    iocs_data = await db.get_iocs(confidence="high", page_size=50, date_from=date_from)
    victims_data = await db.get_victims(date_from=date_from, page_size=100)
    high_iocs = iocs_data.get("items", [])
    victims = victims_data.get("items", [])
    # Build IOC sample text
    ioc_sample_lines = []
    for i in high_iocs[:15]:
        ioc_sample_lines.append(f"- `{i['ioc']}` ({i['ioc_type']}) — {i.get('malware','?')} — conf:{i.get('confidence_label','?')}")
    top_actors = [a["threat_actor"] for a in stats.get("top_threat_actors", [])[:5]]
    top_groups = [g["group_name"] for g in stats.get("top_ransomware_groups", [])[:5]]
    malware_counts = {}
    for i in high_iocs:
        m = i.get("malware","")
        if m: malware_counts[m] = malware_counts.get(m,0)+1
    top_malware = sorted(malware_counts, key=lambda x: malware_counts[x], reverse=True)[:5]
    countries = list({v.get("country","") for v in victims if v.get("country")})[:8]
    industries = list({v.get("industry","") for v in victims if v.get("industry")})[:8]
    cves = [i["ioc"] for i in high_iocs if i.get("ioc_type")=="cve"][:8]
    threat_data = {
        "type": "Weekly Threat Advisory",
        "title": req.title or f"CyberXTron Threat Advisory — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "period": f"Last {req.days} days",
        "total_iocs": stats.get("total_iocs", 0),
        "high_conf_iocs": stats.get("high_confidence_iocs", 0),
        "new_victims": len(victims),
        "top_actors": top_actors,
        "top_groups": top_groups,
        "top_malware": top_malware,
        "countries": countries,
        "industries": industries,
        "cves": cves,
        "ioc_sample": "\n".join(ioc_sample_lines),
    }
    advisory_text = await ai.generate_advisory(threat_data)
    report_id = await db.save_report({
        "title": threat_data["title"],
        "summary": advisory_text[:500],
        "threat_actor": ", ".join(top_actors),
        "malware": ", ".join(top_malware),
        "targeted_countries": countries,
        "targeted_industries": industries,
        "cves": cves,
        "impact": f"{len(victims)} victims in {req.days} days",
        "iocs": [{"ioc": i["ioc"], "type": i["ioc_type"], "confidence": i.get("confidence_label","")} for i in high_iocs[:20]],
        "techniques": [],
        "raw_markdown": advisory_text,
    })
    return {"report_id": report_id, "advisory": advisory_text, "data": threat_data}


@ai_router.post("/chat")
async def ai_chat(req: ChatRequest):
    """General threat intelligence AI chat. Now supports agentic tool-use mode."""
    ai = get_ai()
    # If the message is long or looks like a question requiring data, use the agent
    # Or just use the agent by default for better intelligence
    try:
        response = await ai.chat_agent(req.message)
    except Exception as e:
        logger.error("Agent chat failed: %s", e)
        response = await ai.chat(req.message, req.context)
    return {"response": response}


@ai_router.get("/health")
async def ai_health():
    """Detailed health check of all AI providers."""
    ai = get_ai()
    health = await ai.get_ai_health()
    return health


@ai_router.post("/provider/select")
async def select_provider(req: ProviderSelectRequest):
    """Switch AI provider at runtime (user-driven manual selection)."""
    from config import settings
    provider = req.provider.lower().strip()
    valid = ["groq", "ollama", "openrouter", "anthropic"]
    if provider not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid provider. Choose from: {valid}")
    settings.AI_PROVIDER = provider
    ai = get_ai()
    if ai:
        ai.provider = provider
    logger.info("AI provider manually switched to: %s", provider)
    return {"status": "success", "provider": provider, "message": f"AI provider set to {provider.upper()}"}


@ai_router.get("/provider/status")
async def provider_status():
    """Check which AI provider is active, its usage count, and connectivity."""
    from config import settings
    active = getattr(settings, "AI_PROVIDER", "groq").strip().lower()
    last_used = getattr(settings, "_last_used_provider", active)
    usage = getattr(settings, "_provider_usage", {})

    provider_info = {
        "groq":       {"configured": bool(getattr(settings, "GROQ_API_KEY", "")),       "model": getattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile"),           "setup_url": "https://console.groq.com"},
        "openrouter": {"configured": bool(getattr(settings, "OPENROUTER_API_KEY", "")), "model": getattr(settings, "OPENROUTER_MODEL", "google/gemma-3-27b-it:free"),   "setup_url": "https://openrouter.ai"},
        "anthropic":  {"configured": bool(getattr(settings, "ANTHROPIC_API_KEY", "")),  "model": "claude-haiku-4-5-20251001",                                            "setup_url": "https://console.anthropic.com"},
        "ollama":     {"configured": True,                                               "model": getattr(settings, "OLLAMA_MODEL", "gemma3:4b"),                        "setup_url": "https://ollama.ai"},
    }

    for key, info in provider_info.items():
        info["usage_count"] = usage.get(key, 0)
        info["is_active"] = (key == active)
        info["last_used"] = (key == last_used)

    return {
        "active_provider":    active,
        "last_used_provider": last_used,
        "providers":          provider_info,
    }
