from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, HttpUrl, Field


class IndicatorBase(BaseModel):
    type: str
    value: str


class IndicatorRead(IndicatorBase):
    id: int

    class Config:
        from_attributes = True


class CVEReferenceRead(BaseModel):
    id: int
    cve_id: str

    class Config:
        from_attributes = True


class CompanyBase(BaseModel):
    name: str
    slug: str
    official_site: Optional[HttpUrl] = None


class CompanyRead(CompanyBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class CompanySummary(CompanyRead):
    incident_count: int


class IncidentBase(BaseModel):
    title: str
    summary: Optional[str] = None
    threat_actor: Optional[str] = None
    malware_name: Optional[str] = None
    countries: List[str] = Field(default_factory=list)
    industries: List[str] = Field(default_factory=list)
    affected_products: Optional[str] = None
    cve_ids: List[str] = Field(default_factory=list)
    impact: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    source_link: HttpUrl
    published_at: Optional[datetime] = None
    source_type: str


class IncidentSummary(IncidentBase):
    id: int
    company_id: Optional[int]
    company_name: Optional[str]
    detected_at: datetime

    class Config:
        from_attributes = True


class IncidentDetail(IncidentSummary):
    indicators: List[IndicatorRead] = Field(default_factory=list)
    cves: List[CVEReferenceRead] = Field(default_factory=list)


class TimelineDay(BaseModel):
    date: str
    incidents: List[IncidentSummary]

