from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from . import models
from .ai import generate_advisory_summary
from .collector.base import RawItem


IOC_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b"
)
IOC_DOMAIN_RE = re.compile(
    r"\b(?!(?:\d{1,3}\.){3}\d{1,3})[a-zA-Z0-9.-]+\.(?:[a-zA-Z]{2,})\b"
)
IOC_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IOC_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
ONION_RE = re.compile(
    r"\b(?:https?://)?[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?\b", re.IGNORECASE
)
THREAT_ACTOR_RE = re.compile(
    r"\b(?:APT\d{1,3}|Lazarus|FIN\d{1,3}|LockBit|Cl0p|BlackCat|ALPHV|Scattered Spider|"
    r"Sandworm|Volt Typhoon|Mustang Panda|Cozy Bear|Fancy Bear)\b",
    re.IGNORECASE,
)
MALWARE_RE = re.compile(
    r"\b(?:Emotet|TrickBot|QakBot|Cobalt Strike|DarkGate|IcedID|RedLine|Agent Tesla|"
    r"Rhadamanthys|Lumma|XWorm|PlugX|BlackEnergy)\b",
    re.IGNORECASE,
)

COUNTRIES = {
    "united states",
    "ukraine",
    "russia",
    "china",
    "iran",
    "north korea",
    "india",
    "germany",
    "france",
    "uk",
    "united kingdom",
    "japan",
    "australia",
    "canada",
    "brazil",
}
INDUSTRIES = {
    "healthcare",
    "finance",
    "financial",
    "banking",
    "government",
    "telecommunications",
    "technology",
    "energy",
    "manufacturing",
    "retail",
    "education",
    "defense",
}


def extract_iocs(text: str) -> Tuple[List[str], List[str], List[str], List[str], List[str]]:
    ips = sorted(set(IOC_IP_RE.findall(text)))
    domains = sorted(set(IOC_DOMAIN_RE.findall(text)))
    hashes = sorted(set(IOC_HASH_RE.findall(text)))
    urls = sorted(set(IOC_URL_RE.findall(text)))
    onion_urls = sorted(
        set(
            (
                link
                if link.lower().startswith("http")
                else f"http://{link}"
            )
            for link in ONION_RE.findall(text)
        )
    )
    return ips, domains, hashes, urls, onion_urls


def extract_mitre(text: str) -> List[str]:
    return sorted(set(MITRE_RE.findall(text)))


def extract_cves(text: str) -> List[str]:
    return sorted(set(match.upper() for match in CVE_RE.findall(text)))


def _first_match(regex: re.Pattern[str], text: str) -> Optional[str]:
    m = regex.search(text)
    return m.group(0) if m else None


def extract_countries(text: str) -> List[str]:
    lowered = text.lower()
    return sorted({c.title() for c in COUNTRIES if c in lowered})


def extract_industries(text: str) -> List[str]:
    lowered = text.lower()
    normalized = {
        "Financial Services" if i in {"finance", "financial", "banking"} else i.title()
        for i in INDUSTRIES
        if i in lowered
    }
    return sorted(normalized)


def infer_affected_products(text: str, company: Optional[models.Company]) -> Optional[str]:
    if company and company.name:
        return f"Potentially affected {company.name} products and services."
    return None


def infer_impact(text: str) -> Optional[str]:
    lowered = text.lower()
    if "remote code execution" in lowered:
        return "Potential remote code execution impact."
    if "privilege escalation" in lowered:
        return "Potential privilege escalation impact."
    if "data breach" in lowered or "data leak" in lowered:
        return "Potential data exposure or breach impact."
    if "denial of service" in lowered or "dos" in lowered:
        return "Potential denial-of-service impact."
    if "ransomware" in lowered:
        return "Potential ransomware-related operational impact."
    return None


def abuseipdb_high_confidence_hits(ips: List[str]) -> List[str]:
    api_key = __import__("os").getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return []
    hits: List[str] = []
    headers = {"Key": api_key, "Accept": "application/json"}
    for ip in ips[:3]:
        try:
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=8,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            if score >= 75:
                hits.append(f"{ip} ({score})")
        except Exception:
            continue
    return hits


def normalize_raw_item(
    raw: RawItem,
    source: models.Source,
    company: Optional[models.Company],
) -> models.Incident:
    """
    Build an Incident instance (not yet persisted) from a RawItem.
    """
    full_text = " ".join(
        s for s in [raw.title, raw.summary_raw or "", raw.content or ""] if s
    )
    cves = extract_cves(full_text)
    ips, domains, hashes, urls, onion_urls = extract_iocs(full_text)
    mitre = extract_mitre(full_text)
    threat_actor = _first_match(THREAT_ACTOR_RE, full_text)
    malware_name = _first_match(MALWARE_RE, full_text)
    countries = extract_countries(full_text)
    industries = extract_industries(full_text)
    affected_products = infer_affected_products(full_text, company)
    impact = infer_impact(full_text)
    high_confidence_ips = abuseipdb_high_confidence_hits(ips)
    if high_confidence_ips:
        note = f"High-confidence malicious IPs detected via AbuseIPDB: {', '.join(high_confidence_ips)}."
        impact = f"{impact} {note}".strip() if impact else note

    advisory_summary = generate_advisory_summary(
        raw.title or raw.url, full_text or raw.summary_raw or ""
    )

    incident = models.Incident(
        company_id=company.id if company else None,
        source_id=source.id,
        title=raw.title or raw.url,
        summary=advisory_summary,
        threat_actor=threat_actor,
        malware_name=malware_name,
        countries=json.dumps(countries) if countries else None,
        industries=json.dumps(industries) if industries else None,
        affected_products=affected_products,
        cve_ids=json.dumps(cves) if cves else None,
        impact=impact,
        mitre_techniques=json.dumps(mitre) if mitre else None,
        source_link=raw.url,
        published_at=raw.published_at_raw or datetime.utcnow(),
        source_type=(
            models.IncidentSourceType.OFFICIAL_VENDOR_DISCLOSURE
            if source.type == models.SourceType.OFFICIAL_VENDOR
            else models.IncidentSourceType.EXTERNAL_INTELLIGENCE_REPORT
        ),
    )

    indicators = []
    for ip in ips:
        indicators.append(models.Indicator(type=models.IndicatorType.IP, value=ip))
    for d in domains:
        indicators.append(models.Indicator(type=models.IndicatorType.DOMAIN, value=d))
    for h in hashes:
        indicators.append(models.Indicator(type=models.IndicatorType.HASH, value=h))
    for u in urls:
        indicators.append(models.Indicator(type=models.IndicatorType.URL, value=u))
    for onion in onion_urls:
        indicators.append(models.Indicator(type=models.IndicatorType.URL, value=onion))

    incident.indicators = indicators
    incident.cves = [models.CVEReference(cve_id=cve) for cve in cves]

    return incident


def upsert_incident(db: Session, incident: models.Incident) -> Optional[models.Incident]:
    """
    Insert an incident if it doesn't exist yet (by source_id + source_link).
    Returns the persisted incident or None if skipped as duplicate.
    """
    existing = (
        db.query(models.Incident)
        .filter(
            models.Incident.source_id == incident.source_id,
            models.Incident.source_link == incident.source_link,
        )
        .first()
    )
    if existing:
        return None

    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident

