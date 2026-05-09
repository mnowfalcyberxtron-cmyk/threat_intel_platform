"""
api/advisory_routes.py — Top 25 Companies Advisory + Core Threat Advisory endpoints.
Produces CyberXTron-structured advisories with AI analysis.
"""
import json
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

logger = logging.getLogger("api.advisory")
advisory_router = APIRouter(prefix="/api/advisory", tags=["Advisory Monitor"])

_db = None
_ai = None
_scheduler = None


def _uniq_keep_order(values):
    out, seen = [], set()
    for v in values:
        if not v:
            continue
        key = str(v).strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(str(v).strip())
    return out


@advisory_router.get("/")
async def list_advisories(
    page:         int           = Query(1, ge=1),
    page_size:    int           = Query(50, ge=1, le=200),
    company:      Optional[str] = None,
    severity:     Optional[str] = None,
    category:     Optional[str] = None,
    advisory_type: Optional[str]= None,
    search:       Optional[str] = None,
    hours:        int           = Query(168, ge=1, le=720),
):
    """List advisories with filters. Default: last 7 days."""
    return await _db.get_advisories(
        page=page, page_size=page_size, company=company,
        severity=severity, category=category,
        advisory_type=advisory_type, search=search, hours=hours,
    )


@advisory_router.get("/stats")
async def advisory_stats():
    """Advisory statistics — company counts, severity breakdown."""
    return await _db.get_advisory_stats()


@advisory_router.get("/companies")
async def company_list():
    """List all companies with advisory counts."""
    async with _db._conn.execute(
        """SELECT company, advisory_type, COUNT(*) as cnt,
           SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical_count
           FROM advisories
           WHERE fetched_at >= datetime('now','-7 days')
           GROUP BY company, advisory_type
           ORDER BY critical_count DESC, cnt DESC"""
    ) as cur:
        rows = await cur.fetchall()
    return {"companies": [dict(r) for r in rows]}


@advisory_router.get("/critical")
async def critical_advisories(hours: int = Query(72, ge=1, le=168)):
    """Get only critical severity advisories."""
    return await _db.get_advisories(severity="critical", hours=hours, page_size=100)


@advisory_router.post("/{advisory_id}/analyze")
async def analyze_advisory(advisory_id: int):
    """AI analysis of a specific advisory."""
    if not _ai:
        raise HTTPException(503, "AI engine not ready")
    async with _db._conn.execute("SELECT * FROM advisories WHERE id=?", (advisory_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Advisory not found")
    adv = dict(row)
    for f in ("cves","iocs","mitre_ttps"):
        try: adv[f] = json.loads(adv.get(f,"{}") or "{}")
        except: pass

    iocs = adv.get("iocs",{})
    cves = _uniq_keep_order(adv.get("cves", []))
    doms = _uniq_keep_order((iocs or {}).get("domains", []))
    ips = _uniq_keep_order((iocs or {}).get("ips", []))
    title = adv.get("title", "")
    company = adv.get("company", "")

    # Correlate internal IOCs from platform DB (high confidence first).
    internal_hits = []
    seen_iocs = set()
    for needle in (cves + doms + ips)[:20]:
        q = await _db.get_iocs(search=needle, page_size=20)
        for i in (q or {}).get("items", []):
            val = i.get("ioc", "")
            if val and val not in seen_iocs:
                seen_iocs.add(val)
                internal_hits.append(i)
    if not internal_hits:
        # Fallback by advisory text/company signal
        q = await _db.get_iocs(search=title or company, page_size=30)
        internal_hits = (q or {}).get("items", [])

    # Correlate likely victims using advisory context.
    victim_q = await _db.get_victims(search=company or title, page_size=20)
    mapped_victims = [v for v in (victim_q or {}).get("items", [])
                      if (v.get("victim_name") and v.get("victim_name") not in {"?", "unknown"})]

    # Pull external+internal enrichment from live threat feed.
    feed_hits = await _db.search_feed(" ".join((cves[:3] or [title])[:3]), limit=10)
    if not feed_hits:
        feed_hits = await _db.search_feed(title, limit=10)

    mapped_ioc_lines = "\n".join(
        f"- {i.get('ioc')} ({i.get('ioc_type')}) | conf={i.get('confidence_label')} | src={i.get('source_count',1)}"
        for i in internal_hits[:20]
    ) or "- none mapped from internal DB"
    mapped_victim_lines = "\n".join(
        f"- {v.get('victim_name')} | group={v.get('group_name')} | source={v.get('source','')}"
        for v in mapped_victims[:10]
    ) or "- none mapped"
    external_lines = "\n".join(
        f"- {h.get('title','')} | {h.get('source','')} | {h.get('url','')}"
        for h in (feed_hits or [])[:8]
    ) or "- no matching enrichment items"

    prompt = f"""Analyze this security advisory and produce a structured threat intelligence report:

**Company/Product:** {adv['company']}
**Advisory Title:** {adv['title']}
**Severity:** {adv['severity'].upper()}
**Source:** {adv['source_name']} ({adv['advisory_type']})
**Published:** {adv.get('published','?')[:10]}
**CVEs:** {', '.join(cves[:10]) or 'none mentioned'}
**MITRE TTPs Detected:** {', '.join(adv.get('mitre_ttps',[])[:8]) or 'none detected'}
**Domains in Advisory:** {', '.join(doms[:5]) or 'none'}
**IPs in Advisory:** {', '.join(ips[:5]) or 'none'}

**Mapped Internal IOCs (CyberXTron DB):**
{mapped_ioc_lines}

**Mapped Related Victims (CyberXTron DB):**
{mapped_victim_lines}

**External Enrichment (credible monitored sources):**
{external_lines}

**Summary:**
{adv.get('summary','')[:600]}

Produce a structured advisory analysis EXACTLY matching the following format with exactly these headers:

Title: {adv['title']}
Summary: [Concise 2-3 sentence summary of what the vulnerability/threat is]
Threat Actor/Threat Group: [Named actor if mentioned, otherwise "Unknown"]
Malware: [Specific malware or exploit technique involved]
Targeted Countries: [Countries or "Global"]
Targeted Industries: [Industries at risk from this advisory]
Targeted Applications: [Specific software versions/products affected]
Impact: [RCE / Privilege Escalation / Data Exfiltration / DoS / etc.]
IOCs: [List of Domains, IPs, Hashes, CVEs, plus mapped internal IOCs]
MITRE TTPs: [technique IDs]
Source URL: {adv.get('url','')}"""

    analysis = await _ai.chat(prompt)

    # Store analysis
    await _db._conn.execute(
        "UPDATE advisories SET ai_analysis=? WHERE id=?",
        (analysis, advisory_id)
    )
    await _db._conn.commit()

    return {
        "advisory_id": advisory_id,
        "advisory": adv,
        "analysis": analysis,
        "mapped_iocs": internal_hits[:30],
        "mapped_victims": mapped_victims[:20],
        "external_enrichment": (feed_hits or [])[:10],
    }


@advisory_router.post("/refresh")
async def refresh_advisories(background_tasks: BackgroundTasks):
    """Trigger immediate advisory refresh."""
    from connectors.advisory_monitor import AdvisoryMonitorConnector
    async def run():
        conn = AdvisoryMonitorConnector()
        records = await conn.run()
        new = 0
        for r in records:
            if r.get("type") == "advisory":
                _, is_new = await _db.upsert_advisory(r)
                if is_new: new += 1
        await _db.update_source_status("advisory_monitor", "ok", new)
        await _db.log("INFO", "advisory_monitor", f"+{new} new advisories")
    background_tasks.add_task(run)
    return {"status": "triggered", "message": "Advisory refresh running in background"}


@advisory_router.get("/core-threat-report")
async def core_threat_report():
    """
    CyberXTron FinalFeed Core Monitoring report.
    Combines IOCs, victims, advisories into a unified structured output.
    """
    if not _ai:
        raise HTTPException(503, "AI engine not ready")

    stats   = await _db.get_stats()
    iocs    = await _db.get_iocs(confidence="high", page_size=20)
    victims = await _db.get_victims(page_size=20)
    advisories = await _db.get_advisories(severity="critical", hours=72, page_size=10)

    ioc_lines  = "\n".join(
        f"- `{i['ioc']}` ({i['ioc_type']}) — {i.get('malware','?')} | conf:{i.get('confidence_label','?')}"
        for i in iocs.get("items",[])[:15]
    )
    vic_lines  = "\n".join(
        f"- {v['victim_name']} | Group: {v['group_name']} | {v.get('country','?')} | {v.get('industry','?')}"
        for v in victims.get("items",[])[:10]
    )
    adv_lines  = "\n".join(
        f"- [{a['severity'].upper()}] {a['company']}: {a['title'][:80]}"
        for a in advisories.get("items",[])[:10]
    )

    prompt = f"""Generate a CyberXTron FinalFeed Core Threat Monitoring report.

Platform data:
- Total IOCs: {stats.get('total_iocs',0):,}
- High Confidence: {stats.get('high_confidence_iocs',0):,}
- Ransomware Victims: {stats.get('total_victims',0):,}
- New IOCs (24h): {stats.get('new_iocs_24h',0):,}
- New Victims (24h): {stats.get('new_victims_24h',0):,}

High-Confidence IOCs:
{ioc_lines or 'none yet'}

Recent Ransomware Victims:
{vic_lines or 'none yet'}

Critical Advisories:
{adv_lines or 'none yet'}

Produce:

== SECTION 1 — CyberXtron FinalFeed Core Threat Monitoring ==

For each significant threat detected, produce a structured entry:

**Company / Product:** [affected product]
**Advisory Title:** [threat/campaign name]
**Summary:** [2-3 sentence summary]
**Threat Actor / Group:** [actor or "Unknown"]
**Malware / Exploit:** [specific malware/exploit]
**Targeted Countries:** [list or Global]
**Targeted Industries:** [sectors]
**Targeted Applications:** [specific software]
**Impact:** [types of impact]
**IOCs:**
  - Domains: [from platform data]
  - IPs: [from platform data]
  - Hashes: [from platform data]
**MITRE TTPs:** [T-IDs with names]
**Reference URL:** [platform: http://localhost:8000 + authoritative external URL]

[Produce at least 3-5 threat entries based on the platform data above]"""

    report = await _ai.chat(prompt)
    return {"report": report, "generated_at": _db.now_iso() if hasattr(_db, 'now_iso') else ""}
