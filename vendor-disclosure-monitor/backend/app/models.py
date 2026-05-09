from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column

from .database import Base


class SourceType(str):
    OFFICIAL_VENDOR = "OFFICIAL_VENDOR"
    EXTERNAL_INTEL = "EXTERNAL_INTEL"


class SourceSubtype(str):
    RSS = "RSS"
    HTML_PAGE = "HTML_PAGE"
    API = "API"
    GITHUB = "GITHUB"
    NVD = "NVD"


class IncidentSourceType(str):
    OFFICIAL_VENDOR_DISCLOSURE = "OFFICIAL_VENDOR_DISCLOSURE"
    EXTERNAL_INTELLIGENCE_REPORT = "EXTERNAL_INTELLIGENCE_REPORT"


class IndicatorType(str):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    official_site: Mapped[Optional[str]] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    sources: Mapped[list["Source"]] = relationship("Source", back_populates="company")
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident", back_populates="company"
    )


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    company_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("companies.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(
        String(32), nullable=False, default=SourceType.OFFICIAL_VENDOR
    )
    subtype: Mapped[str] = mapped_column(String(32), nullable=False)
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    parser_hint: Mapped[Optional[str]] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    poll_interval_minutes: Mapped[int] = mapped_column(Integer, default=5)

    company: Mapped[Optional["Company"]] = relationship(
        "Company", back_populates="sources"
    )
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident", back_populates="source"
    )


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "source_link",
            name="uq_incident_source_link",
        ),
        Index("ix_incidents_company_published", "company_id", "published_at"),
        Index("ix_incidents_source_type", "source_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    company_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("companies.id"), nullable=True
    )
    source_id: Mapped[int] = mapped_column(Integer, ForeignKey("sources.id"))

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(255))
    malware_name: Mapped[Optional[str]] = mapped_column(String(255))
    countries: Mapped[Optional[str]] = mapped_column(Text)  # JSON string
    industries: Mapped[Optional[str]] = mapped_column(Text)  # JSON string
    affected_products: Mapped[Optional[str]] = mapped_column(Text)
    cve_ids: Mapped[Optional[str]] = mapped_column(Text)  # JSON string or CSV
    impact: Mapped[Optional[str]] = mapped_column(Text)
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text)  # JSON string

    source_link: Mapped[str] = mapped_column(String(1000), nullable=False)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    source_type: Mapped[str] = mapped_column(
        String(64),
        default=IncidentSourceType.OFFICIAL_VENDOR_DISCLOSURE,
        nullable=False,
    )

    company: Mapped[Optional["Company"]] = relationship(
        "Company", back_populates="incidents"
    )
    source: Mapped["Source"] = relationship("Source", back_populates="incidents")
    indicators: Mapped[list["Indicator"]] = relationship(
        "Indicator", back_populates="incident", cascade="all, delete-orphan"
    )
    cves: Mapped[list["CVEReference"]] = relationship(
        "CVEReference", back_populates="incident", cascade="all, delete-orphan"
    )


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id"))
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="indicators"
    )


class CVEReference(Base):
    __tablename__ = "cve_references"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id"))
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="cves")

