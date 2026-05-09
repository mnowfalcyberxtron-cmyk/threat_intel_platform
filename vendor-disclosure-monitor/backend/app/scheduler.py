from __future__ import annotations

import logging
from typing import Dict, List, Optional, Type

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

from . import config, database, ingestion, models
from .collector.api_collector import APICollector
from .collector.base import BaseCollector
from .collector.github_collector import GitHubCollector
from .collector.html_collector import HTMLCollector
from .collector.rss_collector import RSSCollector

logger = logging.getLogger(__name__)


COLLECTOR_REGISTRY: Dict[str, Type[BaseCollector]] = {
    models.SourceSubtype.RSS: RSSCollector,
    models.SourceSubtype.HTML_PAGE: HTMLCollector,
    models.SourceSubtype.API: APICollector,
    models.SourceSubtype.GITHUB: GitHubCollector,
}


class MonitoringScheduler:
    def __init__(self) -> None:
        self.scheduler = BackgroundScheduler()
        self._started = False

    def start(self) -> None:
        if not self._started:
            self.scheduler.start()
            self._started = True

    def shutdown(self) -> None:
        if self._started:
            self.scheduler.shutdown(wait=False)
            self._started = False

    def schedule_jobs(self, db: Session) -> None:
        """
        Create jobs for all enabled sources based on poll_interval_minutes.
        """
        sources: List[models.Source] = (
            db.query(models.Source)
            .filter(models.Source.enabled == True)  # noqa: E712
            .all()
        )
        for source in sources:
            minutes = max(source.poll_interval_minutes or config.settings.poll_interval_minutes, 1)
            job_id = f"source-{source.id}"
            if self.scheduler.get_job(job_id):
                continue

            trigger = IntervalTrigger(minutes=minutes)
            self.scheduler.add_job(
                func=run_collection_job,
                trigger=trigger,
                id=job_id,
                kwargs={"source_id": source.id},
                replace_existing=True,
            )
            logger.info("Scheduled monitoring job for source %s (%s minutes)", source.id, minutes)


def load_vendors_config(db: Session) -> None:
    """
    Read vendors.yaml and upsert companies and sources.
    """
    path = config.settings.vendors_config_path
    if not path.exists():
        logger.warning("Vendors config not found at %s", path)
        return

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    companies = data.get("companies", [])
    external_sources = data.get("external_sources", [])

    # Upsert companies and their sources
    for company_cfg in companies:
        name = company_cfg["name"]
        slug = company_cfg["slug"]
        official_site = company_cfg.get("official_site")

        company = db.query(models.Company).filter(models.Company.slug == slug).first()
        if not company:
            company = models.Company(name=name, slug=slug, official_site=official_site)
            db.add(company)
            db.commit()
            db.refresh(company)
        else:
            updated = False
            if company.official_site != official_site and official_site:
                company.official_site = official_site
                updated = True
            if updated:
                db.commit()

        for src_cfg in company_cfg.get("sources", []):
            _upsert_source(db, src_cfg, company_id=company.id)

    # Global external sources not tied to a single company
    for src_cfg in external_sources:
        _upsert_source(db, src_cfg, company_id=None)


def _upsert_source(db: Session, cfg: dict, company_id: Optional[int]) -> None:
    name = cfg["name"]
    url = cfg["url"]
    type_ = cfg.get("type", models.SourceType.OFFICIAL_VENDOR)
    subtype = cfg.get("subtype", models.SourceSubtype.RSS)
    parser_hint = cfg.get("parser_hint")
    poll_interval_minutes = int(cfg.get("poll_interval_minutes", config.settings.poll_interval_minutes))

    existing = (
        db.query(models.Source)
        .filter(
            models.Source.company_id.is_(company_id),
            models.Source.name == name,
            models.Source.url == url,
        )
        .first()
    )
    if existing:
        updated = False
        if existing.type != type_:
            existing.type = type_
            updated = True
        if existing.subtype != subtype:
            existing.subtype = subtype
            updated = True
        if existing.parser_hint != parser_hint:
            existing.parser_hint = parser_hint
            updated = True
        if existing.poll_interval_minutes != poll_interval_minutes:
            existing.poll_interval_minutes = poll_interval_minutes
            updated = True
        if updated:
            db.commit()
        return

    source = models.Source(
        company_id=company_id,
        name=name,
        type=type_,
        subtype=subtype,
        url=url,
        parser_hint=parser_hint,
        poll_interval_minutes=poll_interval_minutes,
        enabled=True,
    )
    db.add(source)
    db.commit()


def run_collection_job(source_id: int) -> int:
    """
    Fetch data for a single source and persist new incidents.
    Returns number of new incidents created.
    """
    db_session = next(database.get_db())
    try:
        source = db_session.query(models.Source).filter(models.Source.id == source_id).first()
        if not source or not source.enabled:
            return 0
        company = source.company

        collector_cls = COLLECTOR_REGISTRY.get(source.subtype)
        if not collector_cls:
            logger.warning("No collector registered for subtype %s", source.subtype)
            return 0

        collector = collector_cls()
        count_new = 0
        for raw in collector.fetch(source):
            incident = ingestion.normalize_raw_item(raw, source, company)
            persisted = ingestion.upsert_incident(db_session, incident)
            if persisted:
                count_new += 1

        logger.info("Source %s: collected %s new incidents", source.id, count_new)
        return count_new
    except Exception:
        logger.exception("Error running collection job for source %s", source_id)
        return 0
    finally:
        db_session.close()


monitoring_scheduler = MonitoringScheduler()

