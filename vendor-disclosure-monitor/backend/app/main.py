from __future__ import annotations

from datetime import datetime
import json
from typing import List, Optional

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import settings
from .database import init_db, get_db
from . import models, schemas
from .scheduler import monitoring_scheduler, load_vendors_config, run_collection_job
from .ai import get_ai_health, get_selected_provider, set_selected_provider


def _as_list(value: Optional[str]) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
    except Exception:
        pass
    return [s.strip() for s in value.split(",") if s.strip()]


app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    # Load vendor and source configuration
    db = next(get_db())
    try:
        load_vendors_config(db)
        monitoring_scheduler.schedule_jobs(db)
        monitoring_scheduler.start()
    finally:
        db.close()


@app.on_event("shutdown")
def on_shutdown() -> None:
    monitoring_scheduler.shutdown()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


@app.get("/ai/health")
def ai_health() -> dict:
    """
    Report live AI provider availability and which provider is active.
    """
    return get_ai_health()


@app.get("/ai/provider")
def ai_provider() -> dict:
    return {"selected_provider": get_selected_provider()}


@app.post("/ai/provider")
def set_ai_provider(provider: str = Query(..., description="auto|ollama|openrouter|groq")) -> dict:
    selected = set_selected_provider(provider)
    return {"selected_provider": selected}


@app.post("/refresh")
def manual_refresh(db: Session = Depends(get_db)) -> dict:
    """
    Manually trigger an immediate collection run for all enabled sources.
    """
    sources = (
        db.query(models.Source)
        .filter(models.Source.enabled == True)  # noqa: E712
        .all()
    )
    total_new = 0
    for src in sources:
        total_new += run_collection_job(src.id)
    return {"status": "ok", "new_incidents": total_new}


@app.get("/companies", response_model=List[schemas.CompanySummary])
def list_companies(db: Session = Depends(get_db)) -> List[schemas.CompanySummary]:
    from sqlalchemy import func

    q = (
        db.query(
            models.Company,
            func.count(models.Incident.id).label("incident_count"),
        )
        .outerjoin(models.Incident, models.Incident.company_id == models.Company.id)
        .group_by(models.Company.id)
        .order_by(models.Company.name)
    )
    results: list[schemas.CompanySummary] = []
    for company, incident_count in q.all():
        results.append(
            schemas.CompanySummary(
                id=company.id,
                name=company.name,
                slug=company.slug,
                official_site=company.official_site,
                created_at=company.created_at,
                incident_count=incident_count,
            )
        )
    return results


@app.get("/companies/{company_id}", response_model=schemas.CompanySummary)
def get_company(company_id: int, db: Session = Depends(get_db)) -> schemas.CompanySummary:
    from sqlalchemy import func

    company = db.query(models.Company).filter(models.Company.id == company_id).first()
    if not company:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Company not found")

    incident_count = (
        db.query(func.count(models.Incident.id))
        .filter(models.Incident.company_id == company_id)
        .scalar()
    )
    return schemas.CompanySummary(
        id=company.id,
        name=company.name,
        slug=company.slug,
        official_site=company.official_site,
        created_at=company.created_at,
        incident_count=incident_count or 0,
    )


@app.get("/incidents", response_model=List[schemas.IncidentSummary])
def list_incidents(
    db: Session = Depends(get_db),
    q: Optional[str] = Query(default=None, description="Search in title and summary"),
    company_id: Optional[int] = None,
    threat_actor: Optional[str] = None,
    malware_name: Optional[str] = None,
    cve_id: Optional[str] = None,
    industry: Optional[str] = None,
    country: Optional[str] = None,
    source_type: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    limit: int = 100,
) -> List[schemas.IncidentSummary]:
    query = (
        db.query(models.Incident, models.Company.name.label("company_name"))
        .outerjoin(models.Company, models.Company.id == models.Incident.company_id)
        .order_by(models.Incident.published_at.desc().nullslast())
    )

    if q:
        from sqlalchemy import or_

        like = f"%{q}%"
        query = query.filter(
            or_(models.Incident.title.ilike(like), models.Incident.summary.ilike(like))
        )
    if company_id:
        query = query.filter(models.Incident.company_id == company_id)
    if threat_actor:
        query = query.filter(models.Incident.threat_actor == threat_actor)
    if malware_name:
        query = query.filter(models.Incident.malware_name == malware_name)
    if cve_id:
        like = f"%{cve_id}%"
        query = query.filter(models.Incident.cve_ids.ilike(like))
    if industry:
        like = f"%{industry}%"
        query = query.filter(models.Incident.industries.ilike(like))
    if country:
        like = f"%{country}%"
        query = query.filter(models.Incident.countries.ilike(like))
    if source_type:
        query = query.filter(models.Incident.source_type == source_type)
    if date_from:
        query = query.filter(models.Incident.published_at >= date_from)
    if date_to:
        query = query.filter(models.Incident.published_at <= date_to)

    query = query.limit(limit)

    results: list[schemas.IncidentSummary] = []
    for incident, company_name in query.all():
        results.append(
            schemas.IncidentSummary(
                id=incident.id,
                title=incident.title,
                summary=incident.summary,
                threat_actor=incident.threat_actor,
                malware_name=incident.malware_name,
                countries=_as_list(incident.countries),
                industries=_as_list(incident.industries),
                affected_products=incident.affected_products,
                cve_ids=_as_list(incident.cve_ids),
                impact=incident.impact,
                mitre_techniques=_as_list(incident.mitre_techniques),
                source_link=incident.source_link,
                published_at=incident.published_at,
                source_type=incident.source_type,
                company_id=incident.company_id,
                company_name=company_name,
                detected_at=incident.detected_at,
            )
        )
    return results


@app.get("/incidents/{incident_id}", response_model=schemas.IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> schemas.IncidentDetail:
    incident = (
        db.query(models.Incident)
        .filter(models.Incident.id == incident_id)
        .first()
    )
    if not incident:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Incident not found")

    company_name = (
        incident.company.name if incident.company is not None else None
    )

    detail = schemas.IncidentDetail(
        id=incident.id,
        title=incident.title,
        summary=incident.summary,
        threat_actor=incident.threat_actor,
        malware_name=incident.malware_name,
        countries=_as_list(incident.countries),
        industries=_as_list(incident.industries),
        affected_products=incident.affected_products,
        cve_ids=_as_list(incident.cve_ids),
        impact=incident.impact,
        mitre_techniques=_as_list(incident.mitre_techniques),
        source_link=incident.source_link,
        published_at=incident.published_at,
        source_type=incident.source_type,
        company_id=incident.company_id,
        company_name=company_name,
        detected_at=incident.detected_at,
        indicators=[
            schemas.IndicatorRead(
                id=i.id,
                type=i.type,
                value=i.value,
            )
            for i in incident.indicators
        ],
        cves=[
            schemas.CVEReferenceRead(
                id=c.id,
                cve_id=c.cve_id,
            )
            for c in incident.cves
        ],
    )
    return detail


@app.get("/timeline", response_model=List[schemas.TimelineDay])
def get_timeline(
    db: Session = Depends(get_db),
    days: int = 7,
) -> List[schemas.TimelineDay]:
    """
    Group incidents by published date (UTC date string) for the last N days.
    """
    from datetime import timedelta

    cutoff = datetime.utcnow() - timedelta(days=days)
    query = (
        db.query(models.Incident, models.Company.name.label("company_name"))
        .outerjoin(models.Company, models.Company.id == models.Incident.company_id)
        .filter(models.Incident.published_at != None)  # noqa: E711
        .filter(models.Incident.published_at >= cutoff)
        .order_by(models.Incident.published_at.desc())
    )

    by_date: dict[str, list[schemas.IncidentSummary]] = {}
    for incident, company_name in query.all():
        key = incident.published_at.date().isoformat()
        by_date.setdefault(key, []).append(
            schemas.IncidentSummary(
                id=incident.id,
                title=incident.title,
                summary=incident.summary,
                threat_actor=incident.threat_actor,
                malware_name=incident.malware_name,
                countries=_as_list(incident.countries),
                industries=_as_list(incident.industries),
                affected_products=incident.affected_products,
                cve_ids=_as_list(incident.cve_ids),
                impact=incident.impact,
                mitre_techniques=_as_list(incident.mitre_techniques),
                source_link=incident.source_link,
                published_at=incident.published_at,
                source_type=incident.source_type,
                company_id=incident.company_id,
                company_name=company_name,
                detected_at=incident.detected_at,
            )
        )

    days_list: list[schemas.TimelineDay] = []
    for date_str in sorted(by_date.keys(), reverse=True):
        days_list.append(
            schemas.TimelineDay(
                date=date_str,
                incidents=by_date[date_str],
            )
        )
    return days_list

