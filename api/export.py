"""
api/export.py — IOC and victim bulk export endpoints.
Supports CSV and JSON formats for use in SIEM, EDR, firewall rules.
"""

import csv
import io
import json
import logging
from typing import Optional

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse, JSONResponse

logger = logging.getLogger("api.export")

export_router = APIRouter(prefix="/api/export", tags=["export"])

_db = None  # Injected by main.py


def get_db():
    return _db


@export_router.get("/iocs.csv")
async def export_iocs_csv(
    ioc_type: Optional[str] = None,
    confidence: Optional[str] = None,
    source: Optional[str] = None,
    threat_actor: Optional[str] = None,
    limit: int = Query(10000, ge=1, le=50000),
):
    """
    Export IOCs as CSV.
    Useful for bulk import into firewalls, SIEMs, EDR platforms.

    Example:
        curl http://localhost:8000/api/export/iocs.csv?confidence=high > high_conf_iocs.csv
    """
    db = get_db()
    data = await db.get_iocs(
        page=1,
        page_size=limit,
        ioc_type=ioc_type,
        confidence=confidence,
        source=source,
        threat_actor=threat_actor,
    )
    items = data.get("items", [])

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["ioc", "ioc_type", "confidence", "confidence_label", "sources",
                    "malware", "threat_actor", "first_seen", "last_seen", "tags"],
        extrasaction="ignore",
    )
    writer.writeheader()
    for item in items:
        row = dict(item)
        # Flatten JSON fields
        try:
            row["sources"] = "|".join(json.loads(row.get("sources", "[]")))
        except Exception:
            row["sources"] = ""
        try:
            row["tags"] = "|".join(json.loads(row.get("tags", "[]")))
        except Exception:
            row["tags"] = ""
        writer.writerow(row)

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatintel_iocs.csv"},
    )


@export_router.get("/iocs.json")
async def export_iocs_json(
    ioc_type: Optional[str] = None,
    confidence: Optional[str] = None,
    limit: int = Query(5000, ge=1, le=50000),
):
    """
    Export IOCs as a JSON array.
    Useful for programmatic integration.
    """
    db = get_db()
    data = await db.get_iocs(
        page=1, page_size=limit, ioc_type=ioc_type, confidence=confidence
    )
    items = data.get("items", [])

    # Parse JSON fields
    for item in items:
        for field in ("sources", "tags"):
            try:
                item[field] = json.loads(item.get(field, "[]"))
            except Exception:
                item[field] = []

    return JSONResponse(
        content={"total": len(items), "iocs": items},
        headers={"Content-Disposition": "attachment; filename=threatintel_iocs.json"},
    )


@export_router.get("/iocs-flat.txt")
async def export_iocs_flat(
    ioc_type: str = Query(..., description="ip | domain | url | md5 | sha256 | cve"),
    confidence: Optional[str] = None,
    limit: int = Query(10000, ge=1, le=100000),
):
    """
    Export a flat list of IOC values, one per line.
    Perfect for blocklist format (firewall, DNS sinkholes, etc).

    Example:
        curl 'http://localhost:8000/api/export/iocs-flat.txt?ioc_type=ip&confidence=high'
    """
    db = get_db()
    data = await db.get_iocs(
        page=1, page_size=limit, ioc_type=ioc_type, confidence=confidence
    )
    lines = "\n".join(item["ioc"] for item in data.get("items", []))
    lines = f"# ThreatIntel TIP Export — Type: {ioc_type} | Confidence: {confidence or 'all'}\n" + lines

    return StreamingResponse(
        iter([lines]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=threatintel_{ioc_type}_blocklist.txt"},
    )


@export_router.get("/victims.csv")
async def export_victims_csv(
    group_name: Optional[str] = None,
    country: Optional[str] = None,
    limit: int = Query(5000, ge=1, le=20000),
):
    """Export ransomware victims as CSV."""
    db = get_db()
    data = await db.get_victims(
        page=1, page_size=limit, group_name=group_name, country=country
    )
    items = data.get("items", [])

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["victim_name", "group_name", "country", "industry",
                    "leak_date", "discovery_date", "website", "description", "status"],
        extrasaction="ignore",
    )
    writer.writeheader()
    for item in items:
        writer.writerow(item)

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatintel_victims.csv"},
    )


@export_router.get("/excel")
async def export_excel(
    year: Optional[int] = Query(None, description="Filter ICS advisories by CVE year (e.g. 2026)"),
    month: Optional[int] = Query(None, description="Filter ICS advisories by month (1-12)"),
    severity: Optional[str] = Query(None, description="Filter ICS advisories by severity"),
    vendor: Optional[str] = Query(None, description="Filter ICS advisories by vendor name"),
    search: Optional[str] = Query(None, description="Filter ICS advisories by text search"),
    filter_mode: str = Query("cve_published", description="'cve_published' or 'advisory'"),
):
    """
    Export comprehensive threat intelligence Excel workbook.
    Includes:
    - ICS Advisories (monthly sheets with critical CVEs highlighted)
    - Breach Markets (uptime status)
    - Onion Sites (status and screenshots)
    - Uptime History (last 30 days)
    """
    db = get_db()
    if not db:
        return JSONResponse(
            status_code=503,
            content={"error": "Database not available"},
        )
    
    try:
        from utils.excel_exporter import ExcelExporter
        from config import settings
        from pathlib import Path
        
        exporter = ExcelExporter(db)
        output_path = await exporter.export(
            year=year,
            month=month,
            severity=severity,
            vendor=vendor,
            search=search,
            filter_mode=filter_mode,
        )
        
        if not output_path or not Path(output_path).exists():
            logger.error("Excel export failed or file not found")
            return JSONResponse(
                status_code=500,
                content={"error": "Excel generation failed"},
            )
        
        # Read the file and stream it
        with open(output_path, "rb") as f:
            content = f.read()
        
        return StreamingResponse(
            iter([content]),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=threatintel_export.xlsx"},
        )
    except ImportError as e:
        logger.error("Excel export dependencies missing: %s", e)
        return JSONResponse(
            status_code=503,
            content={"error": "Excel export dependencies not installed (openpyxl, pandas)"},
        )
    except Exception as e:
        logger.error("Excel export failed: %s", e)
        return JSONResponse(
            status_code=500,
            content={"error": f"Excel export failed: {str(e)[:200]}"},
        )
