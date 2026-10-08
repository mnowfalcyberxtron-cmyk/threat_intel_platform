"""
api/advisory_routes.py — Top 25 Companies Advisory + Core Threat Advisory endpoints.
Produces ThreatIntel-structured advisories with AI analysis.
"""
import json
import logging
import csv
import io
import re
import asyncio
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
import httpx
from config import settings
from connectors.nvd_enrichment import run_nvd_cvss4_enrichment_loop
from connectors.cvelist_enrichment import (
    build_cvelist_index,
    run_cvelist_enrichment_loop,
    run_cvelist_live_sync_loop,
)

logger = logging.getLogger("api.advisory")
advisory_router = APIRouter(prefix="/api/advisory", tags=["Advisory Monitor"])

_db = None
_ai = None
_scheduler = None
_nvd_enrichment_task: Optional[asyncio.Task] = None
_cvelist_bulk_task: Optional[asyncio.Task] = None    # one-time zip enrichment
_cvelist_live_task: Optional[asyncio.Task] = None    # live GitHub poll every 5 min
_cvelist_index: dict = {}

# ── ICS Advisory Cache & Persistence ───────────────────────────────────────
_ICS_CSV_URL = (
    "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/"
    "ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"
)
_RAPIDAPI_HOST = "ics-ap-apis.p.rapidapi.com"
_RAPIDAPI_BASE_URL = f"https://{_RAPIDAPI_HOST}"
_ics_cache: List[Dict] = []
_ics_cache_ts: float = 0.0
_ics_cache_key: str = ""
_ics_enrichment_cache: Dict[str, Dict[str, Any]] = {}
_ics_db_synced: bool = False  # Track if we've synced to SQLite on startup
_ics_sync_lock: asyncio.Lock = asyncio.Lock()

# Cache TTL configuration (seconds)
_ICS_MEMORY_CACHE_TTL = 600  # 10 minutes — reduce API calls
_ICS_DB_CACHE_TTL = 86400    # 24 hours — persistent SQLite cache
_ICS_API_CONCURRENCY = 5      # Max concurrent API requests
_ICS_BATCH_SIZE = 5000        # Max records per DB operation
_ics_api_semaphore: asyncio.Semaphore = asyncio.Semaphore(_ICS_API_CONCURRENCY)


def _should_run_ics_monthly_sync(now: Optional[datetime] = None, *, force: bool = False) -> bool:
    """Only allow ICS API pulls on the 1st of the month unless a manual refresh forces it."""
    if force:
        return True
    if now is None:
        now = datetime.utcnow()
    return now.day == 1


def _ensure_nvd_enrichment_task() -> None:
    """
    Start background enrichment workers once per process:
      • NVD CVSS-v4 enrichment
      • CVEList bulk enrichment (from local zip, runs at startup)
      • CVEList live sync (polls GitHub API every 5 minutes)
    """
    global _nvd_enrichment_task, _cvelist_bulk_task, _cvelist_live_task, _cvelist_index
    if not _db:
        return

    # NVD enrichment
    if not (_nvd_enrichment_task and not _nvd_enrichment_task.done()):
        _nvd_enrichment_task = asyncio.create_task(run_nvd_cvss4_enrichment_loop(_db))

    # CVEList bulk enrichment from local zip (runs once, then exits)
    if not (_cvelist_bulk_task and not _cvelist_bulk_task.done()):
        if not _cvelist_index:
            _cvelist_index = build_cvelist_index("cvelistV5.zip")
        _cvelist_bulk_task = asyncio.create_task(
            run_cvelist_enrichment_loop(_db, _cvelist_index)
        )

    # CVEList live GitHub sync (polls every 5 minutes indefinitely)
    if not (_cvelist_live_task and not _cvelist_live_task.done()):
        github_token = getattr(settings, "GITHUB_TOKEN", "") or None
        _cvelist_live_task = asyncio.create_task(
            run_cvelist_live_sync_loop(
                _db,
                github_token=github_token,
                startup_delay=60.0,   # wait 60s for bulk enrichment to settle first
                poll_interval=300.0,  # then poll every 5 minutes
            )
        )

# CWE → Human-readable impact
_CWE_IMPACT: Dict[str, str] = {
    "CWE-22":  "Path Traversal",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection",
    "CWE-20":  "Improper Input Validation",
    "CWE-23":  "Relative Path Traversal",
    "CWE-35":  "Path Traversal",
    "CWE-59":  "Link Following",
    "CWE-77":  "Command Injection",
    "CWE-88":  "Argument Injection",
    "CWE-91":  "XML Injection",
    "CWE-200": "Information Exposure",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-294": "Authentication Bypass by Capture-replay",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-362": "Race Condition",
    "CWE-502": "Deserialization",
    "CWE-611": "XXE Injection",
    "CWE-639": "Authorization Bypass",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-749": "Dangerous Method Exposure",
    "CWE-770": "Resource Allocation Without Limits",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Stack Buffer Overflow",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-255": "Credentials Management",
    "CWE-256": "Cleartext Storage of Password",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Certificate Validation Failure",
    "CWE-306": "Missing Authentication",
    "CWE-312": "Cleartext Storage of Sensitive Info",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken Crypto Algorithm",
    "CWE-330": "Insufficient Randomness",
    "CWE-345": "Insufficient Verification",
    "CWE-352": "CSRF",
    "CWE-400": "Resource Exhaustion / DoS",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficient Credential Protection",
    "CWE-601": "Open Redirect",
    "CWE-787": "Out-of-Bounds Write / RCE",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-916": "Weak Password Hash",
    "CWE-918": "SSRF",
}

_MONTH_NAMES = [
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]


def _cwe_to_impact(cwe_str: str) -> str:
    """Convert comma-separated CWE list to a readable impact string."""
    if not cwe_str:
        return "Unknown"
    impacts = []
    for cwe in re.split(r"[,;]\s*", cwe_str.strip()):
        cwe = cwe.strip()
        label = _CWE_IMPACT.get(cwe)
        if label and label not in impacts:
            impacts.append(label)
    return ", ".join(impacts) if impacts else "Unknown"


def _parse_affected_and_fixed(products_affected: str):
    """
    Returns (affected_version, fixed_version) from the Products_Affected text.
    Heuristic: anything after '<=', '<', 'prior', 'earlier', 'before' is affected.
    Anything referencing 'fixed', 'patched', 'update', 'HF', 'SP' can hint fixed.
    Returns plain strings suitable for display.
    """
    affected = products_affected.strip() if products_affected else ""
    if not affected:
        return "Unknown", "Unknown"

    # Trim to a reasonable length
    if len(affected) > 200:
        affected_short = affected[:197] + "…"
    else:
        affected_short = affected

    # Attempt to find fixed version hints
    fixed = _derive_fixed_version_hint(affected)
    if _is_placeholder(fixed):
        fix_patterns = [
            r"(?i)(?:fixed in|patched in|resolved in|update to|upgrade to|upgrade to version|update to version)\s*([A-Za-z0-9_.\-+/:]+)",
            r"(?i)(?:HF\d+|SP\d+|hotfix\s*[\d.]+)",
        ]
        for pat in fix_patterns:
            m = re.search(pat, affected)
            if m:
                fixed = (m.group(1) if m.groups() else m.group(0))[:80].strip()
                break

    return affected_short, fixed


def _derive_fixed_version_hint(text: Any) -> str:
    """Best-effort fixed-version extraction from affected-version text."""
    raw = str(text or "").strip()
    if not raw or _is_placeholder(raw):
        return "Unknown"

    patterns = [
        r"(?i)(?:fixed in|patched in|resolved in|update to|upgrade to|upgrade to version|update to version|available in)\s*(?:version\s*)?([A-Za-z0-9][A-Za-z0-9_.\-+/:]*)",
        r"(?i)(?:version|v)\s*([0-9][A-Za-z0-9_.\-+/:]*)\s*(?:and later|or later|or newer|and newer)",
        r"(?i)(?:prior to|before|less than|earlier than|older than|under)\s*(?:v(?:ersion)?\s*)?([A-Za-z0-9][A-Za-z0-9_.\-+/:]*)",
        r"(?i)(?:<|<=)\s*v?([A-Za-z0-9][A-Za-z0-9_.\-+/:]*)",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw)
        if not match:
            continue
        value = (match.group(1) if match.groups() else match.group(0)).strip().lstrip("vV")
        if not value or value.lower() in {"all/*", "all"}:
            continue
        if any(ch.isdigit() for ch in value) or re.search(r"[A-Za-z].*\d|\d.*[A-Za-z]", value):
            return value[:80]
    return "Unknown"


def _derive_patch_available(products_affected: str, cvss: str) -> str:
    """
    Heuristic: if 'fixed', 'patched', 'HF', 'SP', 'update' appears → Yes.
    'will not fix' / 'no patch' → No.
    Otherwise → Yes (assume patch exists for most advisories as per CISA practice).
    """
    text = (products_affected or "").lower()
    text_full = f"{products_affected or ''} {cvss or ''}".lower()
    
    if any(kw in text for kw in ("no fix", "no patch", "will not fix", "no update available", "not fixed")):
        return "No"
    if any(kw in text_full for kw in ("fixed", "patched", "resolved", "update to", "upgrade", " hf", " sp", "hotfix", "firmware", "patch")):
        return "Yes"
    
    # Default: assume Yes for CISA ICS advisories (they typically have patches)
    return "Yes"


def _month_name_to_number(month_str: str) -> Optional[int]:
    if not month_str:
        return None
    month_str = month_str.strip().lower()[:3]
    mapping = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4,
        "may": 5, "jun": 6, "jul": 7, "aug": 8,
        "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    }
    return mapping.get(month_str)


def _parse_date(date_str: str):
    """Parse several common date formats into (year, month) ints."""
    if not date_str:
        return None, None
    s = str(date_str).strip()
    if not s:
        return None, None
    s = s.replace("\u2013", "-").replace("\u2014", "-").replace("/", "-")
    s = re.sub(r"\s+", " ", s)
    s = s.split("T")[0]

    # Try ISO formats
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})", s)
    if m:
        return int(m.group(1)), int(m.group(2))

    # Try US-style dates
    m = re.match(r"^(\d{1,2})-(\d{1,2})-(\d{4})", s)
    if m:
        return int(m.group(3)), int(m.group(1))

    # Try month name formats: March 5 2024, Mar 5, 2024, 5 March 2024
    m = re.match(r"^([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})", s)
    if m:
        month = _month_name_to_number(m.group(1))
        if month:
            return int(m.group(3)), month
    m = re.match(r"^(\d{1,2})\s+([A-Za-z]+),?\s+(\d{4})", s)
    if m:
        month = _month_name_to_number(m.group(2))
        if month:
            return int(m.group(3)), month

    # Try year-month only
    m = re.match(r"^(\d{4})\s+([A-Za-z]+)$", s)
    if m:
        month = _month_name_to_number(m.group(2))
        if month:
            return int(m.group(1)), month

    m = re.match(r"^([A-Za-z]+)\s+(\d{4})$", s)
    if m:
        month = _month_name_to_number(m.group(1))
        if month:
            return int(m.group(2)), month

    # Try bare month number values
    m = re.match(r"^(\d{1,2})$", s)
    if m:
        return None, int(m.group(1))

    return None, None


def _extract_cve_year(cve_id: str):
    m = re.match(r"(?i)CVE-(\d{4})-", cve_id or "")
    return int(m.group(1)) if m else None


def _row_cve_year(row: Dict[str, Any]):
    return row.get("cve_year") or _extract_cve_year(row.get("cve_id", ""))


def _row_filter_month(row: Dict[str, Any]):
    if row.get("month"):
        return row.get("month")
    _, month = _parse_date(
        row.get("published_date") or row.get("release_date") or row.get("last_updated") or ""
    )
    return month


def _first_value(row: Dict[str, Any], *keys: str, default: str = "") -> str:
    """Return the first non-empty scalar-ish value from a source row."""
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            value = ", ".join(str(v).strip() for v in value if str(v).strip())
        value = str(value).strip()
        if value:
            return value
    return default


_PLACEHOLDER_VALUES = {"", "unknown", "n/a", "na", "none", "null", "see advisory", "see vendor advisory"}


def _is_placeholder(value: Any) -> bool:
    return str(value or "").strip().lower() in _PLACEHOLDER_VALUES


def _first_meaningful(row: Dict[str, Any], *keys: str, default: str = "") -> str:
    value = _first_value(row, *keys, default="")
    return default if _is_placeholder(value) else value


def _int_or_none(value: Any) -> Optional[int]:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(float(str(value).strip()))
    except Exception:
        return None


def _split_field(value: Any) -> List[str]:
    """Split CSV strings or API arrays into clean display values."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        raw = []
        for v in value:
            if isinstance(v, dict):
                extracted = v.get("cve") or v.get("cve_id") or v.get("id") or v.get("name") or str(v)
                raw.append(str(extracted).strip())
            else:
                raw.append(str(v).strip())
    else:
        raw = [v.strip() for v in re.split(r"[,;]\s*", str(value)) if v.strip()]
    return [v for v in raw if v and v.lower() not in {"n/a", "na", "none", "null"}]


def _derive_poc_availability(row: Dict[str, Any]) -> str:
    """
    Check multiple sources for POC availability.
    Falls back to: KEV status, then CVSS score inference, then 'Unknown'.
    """
    direct = _first_meaningful(
        row,
        "poc_availability", "POC Availability", "PoC Availability",
        "POC_Availability", "Proof of Concept", "exploit_available",
    )
    if direct:
        return direct
    
    # Check KEV (Known Exploited Vulnerability) field
    kev = _first_value(row, "Known Exploited Vulnerability", "Known Exploited CVE")
    if kev.lower() == "yes":
        return "Yes"
    if kev.lower() == "no":
        return "No"
    
    # Infer from CVSS: High CVSS (>=7.5) or CRITICAL often have public POC
    cvss_str = _first_value(row, "cvss_score", "Cumulative_CVSS", "CVSS")
    severity = _first_value(row, "cvss_severity", "CVSS_Severity", "severity")
    
    try:
        cvss_num = float(cvss_str) if cvss_str else 0
        if cvss_num >= 9.0 or severity.lower() in ("critical", "high"):
            return "Likely"  # High severity often has POC
        if cvss_num >= 7.5:
            return "Likely"
    except (ValueError, AttributeError):
        pass
    
    # Check impact field for exploitation indicators
    impact = _first_value(row, "impact", "Impact", "vulnerability_impact")
    if any(term in impact.lower() for term in ("rce", "execute", "exploit", "code execution", "remote")):
        return "Likely"
    
    return "Unknown"


def _normalise_ics_source_row(row: Dict[str, Any], data_source: str) -> List[Dict]:
    """Normalize CSV, RapidAPI and workbook rows into the CVE-table schema."""
    ics_num   = _first_value(row, "ICS-CERT_Number", "ICS_CERT_Number", "ics_number", "advisory_id")
    title     = _first_value(row, "ICS-CERT_Advisory_Title", "title", "advisory_title")
    vendor    = _first_value(row, "Vendor", "affected_vendor", "vendor")
    product   = _first_value(row, "Product", "affected_application", "product", "affected_product")
    prod_aff  = _first_value(row, "Products_Affected", "Affected_Products", "affected_version", "affected_versions")
    cvss      = _first_value(row, "Cumulative_CVSS", "CVSS", "cvss_score")
    severity  = _first_value(row, "CVSS_Severity", "cvss_severity", "severity")
    cwe       = _first_value(row, "CWE_Number", "cwe", "cwe_id")
    rel_date  = _first_value(row, "Original_Release_Date", "release_date", "published_date", "published")
    upd_date  = _first_value(row, "Last_Updated", "last_updated", "updated")
    year_raw  = row.get("Year", row.get("year", row.get("published_year", "")))
    sector    = _first_value(row, "Critical_Infrastructure_Sector", "sector")
    url       = _first_value(row, "hyperlink", "advisory_url", "url", "source_url")
    
    # RapidAPI actual field names (discovered via /advisories/{id} probe)
    vendor_hq    = _first_value(row, "Company_Headquarters", "Vendor_Headquarters", "vendor_hq", "vendor_headquarters")
    product_dist = _first_value(row, "Product_Distribution", "product_distribution")
    
    # KEV flag — combine both "Known Exploited Vulnerability" and "Known Exploited CVE"
    kev_vuln = _first_value(row, "Known Exploited Vulnerability", "kev_flag", "kev_flagging", "kev")
    kev_cve  = _first_value(row, "Known Exploited CVE", "kev_cve")
    if kev_vuln and kev_cve:
        kev_flag = f"Vuln:{kev_vuln} / CVE:{kev_cve}"
    elif kev_vuln or kev_cve:
        kev_flag = kev_vuln or kev_cve
    else:
        kev_flag = ""
    
    # Extra links
    nist_url = _first_value(row, "NIST_NVD_CVE_URL", "nist_nvd_url")
    csaf_url = _first_value(row, "CISA_CSAF_JSON_ICS_ADV_Links", "csaf_url")

    direct_patch = _first_meaningful(row, "patch_availability", "Patch Availability", "patch_status")
    direct_impact = _first_meaningful(row, "impact", "Impact", "vulnerability_impact")
    direct_affected = _first_meaningful(row, "affected_version", "Affected Version", "affected_versions")
    direct_fixed = _first_meaningful(row, "fixed_version", "Fixed Version", "fixed_versions")

    release_year, release_month = _parse_date(rel_date)
    update_year, update_month = _parse_date(upd_date)
    filter_year, filter_month = _parse_date(rel_date or upd_date)
    if filter_year is None and _int_or_none(year_raw):
        filter_year = _int_or_none(year_raw)
    if release_year is None:
        release_year = _int_or_none(row.get("published_year")) or filter_year
    if update_year is None:
        update_year = _int_or_none(row.get("update_year")) or filter_year
    release_month = release_month or _int_or_none(row.get("published_month"))
    update_month = update_month or _int_or_none(row.get("update_month"))
    filter_month = _int_or_none(row.get("month")) or filter_month or release_month or update_month

    affected_ver, fixed_ver = _parse_affected_and_fixed(prod_aff)
    affected_ver = direct_affected or affected_ver
    fixed_ver = direct_fixed or fixed_ver
    patch_av = direct_patch or _derive_patch_available(" ".join([prod_aff, fixed_ver, url]), cvss)
    impact = direct_impact or _cwe_to_impact(cwe)

    cve_list = _split_field(row.get("CVE_Number", row.get("cve_id", row.get("cves"))))
    if not cve_list:
        cve_list = ["N/A"]
    if not url and ics_num:
        ics_id_lower = ics_num.lower()
        if ics_id_lower.startswith("icsma-"):
            url = f"https://www.cisa.gov/news-events/ics-medical-advisories/{ics_id_lower}"
        else:
            url = f"https://www.cisa.gov/news-events/ics-advisories/{ics_id_lower}"

    rows = []
    for cve in cve_list:
        cve_year = _extract_cve_year(cve)
        rows.append({
            "ics_number":           ics_num,
            "advisory_id":          ics_num,
            "cve_id":               cve,
            "title":                title,
            "patch_availability":   patch_av,
            "poc_availability":     _derive_poc_availability(row),
            "impact":               impact,
            "cvss_score":           cvss,
            "cvss_severity":        severity,
            "affected_vendor":      vendor,
            "affected_application": product,
            "affected_version":     affected_ver,
            "fixed_version":        fixed_ver,
            "cwe":                  cwe,
            "sector":               sector,
            "release_date":         rel_date,
            "last_updated":         upd_date,
            "published_date":       rel_date,
            "published_year":       release_year,
            "published_month":      release_month,
            "year":                 filter_year,
            "month":                filter_month,
            "cve_year":             cve_year,
            "release_year":         release_year,
            "release_month":        release_month,
            "update_year":          update_year,
            "update_month":         update_month,
            "advisory_url":         url,
            "vendor_hq":            vendor_hq,
            "product_distribution": product_dist,
            "kev_flag":             kev_flag,
            "nist_url":             nist_url,
            "csaf_url":             csaf_url,
            "data_source":          data_source,
        })
    return rows


async def _fetch_ics_csv() -> List[Dict]:
    """Download and parse the CISA ICS Advisory master CSV."""
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(_ICS_CSV_URL, headers={"User-Agent": "ThreatIntelTIP/1.0"})
        r.raise_for_status()
    text = r.text
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        rows.extend(_normalise_ics_source_row(row, "csv"))
        continue
        # Raw fields
        ics_num   = row.get("ICS-CERT_Number", "").strip()
        title     = row.get("ICS-CERT_Advisory_Title", "").strip()
        vendor    = row.get("Vendor", "").strip()
        product   = row.get("Product", "").strip()
        prod_aff  = row.get("Products_Affected", "").strip()
        cve_num   = row.get("CVE_Number", "").strip()
        cvss      = row.get("Cumulative_CVSS", "").strip()
        severity  = row.get("CVSS_Severity", "").strip()
        cwe       = row.get("CWE_Number", "").strip()
        rel_date  = row.get("Original_Release_Date", "").strip()
        upd_date  = row.get("Last_Updated", "").strip()
        year_raw  = row.get("Year", "").strip()
        sector    = row.get("Critical_Infrastructure_Sector", "").strip()

        year_int, month_int = _parse_date(rel_date)
        if year_int is None and year_raw.isdigit():
            year_int = int(year_raw)

        affected_ver, fixed_ver = _parse_affected_and_fixed(prod_aff)
        impact    = _cwe_to_impact(cwe)
        patch_av  = _derive_patch_available(prod_aff, cvss)

        # Split multi-CVE rows (some rows have comma-separated CVEs)
        cve_list = [c.strip() for c in re.split(r"[,;]\s*", cve_num) if c.strip()]
        if not cve_list:
            cve_list = ["N/A"]

        for cve in cve_list:
            rows.append({
                "ics_number":         ics_num,
                "advisory_id":        ics_num,
                "cve_id":             cve,
                "title":              title,
                "patch_availability": patch_av,
                "poc_availability":   "Unknown",  # Not in CSV — always Unknown unless future enrichment
                "impact":             impact,
                "cvss_score":         cvss,
                "cvss_severity":      severity,
                "affected_vendor":    vendor,
                "affected_application": product,
                "affected_version":   affected_ver,
                "fixed_version":      fixed_ver,
                "cwe":                cwe,
                "sector":             sector,
                "release_date":       rel_date,
                "last_updated":       upd_date,
                "published_date":     rel_date,
                "published_year":     year_int,
                "published_month":    month_int,
                "year":               year_int,
                "month":              month_int,
                "advisory_url":       f"https://www.cisa.gov/news-events/ics-advisories/{ics_num.lower()}",
            })
    return rows


async def _fetch_ics_rapidapi() -> List[Dict]:
    """Fetch recent ICS advisories through RapidAPI and expand entries to CVE rows."""
    key = getattr(settings, "RAPIDAPI_KEY", "").strip()
    if not key:
        return []

    limit = max(1, min(int(getattr(settings, "ICS_RAPIDAPI_LATEST_LIMIT", 100) or 100), 500))
    headers = {
        "x-rapidapi-host": _RAPIDAPI_HOST,
        "x-rapidapi-key": key,
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        latest = await client.get(f"{_RAPIDAPI_BASE_URL}/advisories/latest/{limit}", headers=headers)
        latest.raise_for_status()
        latest_payload = latest.json()
        summaries = latest_payload.get("result", latest_payload) if isinstance(latest_payload, dict) else latest_payload
        if not isinstance(summaries, list):
            return []

        sem = asyncio.Semaphore(8)

        async def fetch_detail(summary: Dict[str, Any]) -> List[Dict]:
            advisory_id = _first_value(summary, "ICS-CERT_Number", "ics_number")
            if not advisory_id:
                return _normalise_ics_source_row(summary, "rapidapi")
            async with sem:
                try:
                    detail = await client.get(f"{_RAPIDAPI_BASE_URL}/advisories/{advisory_id}", headers=headers)
                    detail.raise_for_status()
                    payload = detail.json()
                    result = payload.get("result", payload) if isinstance(payload, dict) else payload
                    detail_rows = result if isinstance(result, list) else [result]
                    out = []
                    for item in detail_rows:
                        if isinstance(item, dict):
                            merged = {**summary, **item}
                            out.extend(_normalise_ics_source_row(merged, "rapidapi"))
                    return out or _normalise_ics_source_row(summary, "rapidapi")
                except Exception as exc:
                    logger.warning("RapidAPI ICS detail fetch failed for %s: %s", advisory_id, exc)
                    return _normalise_ics_source_row(summary, "rapidapi")

        chunks = await asyncio.gather(*(fetch_detail(s) for s in summaries if isinstance(s, dict)))

    rows: List[Dict] = []
    for chunk in chunks:
        rows.extend(chunk)
    return rows



def _merge_ics_rows(primary_rows: list, fallback_rows: list) -> list:
    merged = {}
    cve_index = {}

    def key_for(row):
        adv = str(row.get("ics_number") or row.get("advisory_id") or "").strip().lower()
        cve = str(row.get("cve_id") or "").strip().upper()
        return (adv, cve)

    def merge_row(base, preferred):
        out = dict(base)
        for k, v in preferred.items():
            if v and str(v).strip() != "N/A" and str(v).strip() != "Unknown":
                out[k] = v
        
        sources = set(f"{base.get('data_source','')},{preferred.get('data_source','')}".split(","))
        out["data_source"] = "+".join([s.strip() for s in sources if s.strip()]) or "csv"
        return out

    for row in fallback_rows:
        row.setdefault("data_source", "csv")
        key = key_for(row)
        merged[key] = row
        if key[1]:
            cve_index.setdefault(key[1], key)
            
    for row in primary_rows:
        row.setdefault("data_source", "rapidapi")
        key = key_for(row)
        target_key = key if key in merged else cve_index.get(key[1], key)
        merged[target_key] = merge_row(merged[target_key], row) if target_key in merged else row
        if key[1]:
            cve_index.setdefault(key[1], target_key)
    return list(merged.values())

def _map_db_row_to_frontend(row: dict) -> dict:
    out = dict(row)
    # Compute standard CVSS severity based on score
    score_val = None
    try:
        if out.get("cvss_score"):
            # Extract leading float from score string (e.g. "8.8" or "8.8 (Web)")
            m_score = re.search(r"(\d+(?:\.\d+)?)", str(out["cvss_score"]))
            if m_score:
                score_val = float(m_score.group(1))
    except (ValueError, TypeError):
        pass

    if score_val is not None:
        if score_val >= 9.0:
            sev_str = "Critical"
        elif score_val >= 7.0:
            sev_str = "High"
        elif score_val >= 4.0:
            sev_str = "Medium"
        elif score_val > 0:
            sev_str = "Low"
        else:
            sev_str = str(row.get("severity") or "").capitalize() or "Unknown"
        out["cvss_severity"] = sev_str
        out["severity"] = sev_str.lower()
    elif "severity" in row:
        out["cvss_severity"] = str(row["severity"]).capitalize() if row["severity"] else ""

    if "vendor" in row:
        out["affected_vendor"] = row["vendor"]
    if "product" in row:
        out["affected_application"] = row["product"]
    if "ics_number" in row:
        out["advisory_id"] = row["ics_number"]
    if "vendor_hq" in row:
        out["vendor_hq"] = row["vendor_hq"]
    if "product_distribution" in row:
        out["product_distribution"] = row["product_distribution"]
    if "kev_flag" in row:
        out["kev_flag"] = row["kev_flag"]
        
    # CVSS score is preserved from db cvss_score (CVSS 3.1 standard priority)
        
    def _is_placeholder(val):
        if not val:
            return True
        v = str(val).strip().lower()
        return v in ("n/a", "unknown", "none", "null", "")

    def _derive_fixed_version_hint(affected):
        if not affected: return "Unknown"
        import re
        aff = str(affected)
        m = re.search(r'(?:prior to|before|through|<=|<)\s*([vV]?\d+(?:\.\d+)*)', aff)
        if m: return "Update to " + m.group(1) + " or later"
        return "Unknown"

    if _is_placeholder(out.get("fixed_version")) and not _is_placeholder(out.get("affected_version")):
        hint = _derive_fixed_version_hint(out.get("affected_version"))
        if not _is_placeholder(hint):
            out["fixed_version"] = hint

    # ── Strip "Affected:" / "Fixed:" label prefixes that AI sometimes adds ──
    _pfx_re = re.compile(r'^(?:affected|fixed)\s*:\s*', re.IGNORECASE)
    for field in ("affected_version", "fixed_version"):
        val = out.get(field) or ""
        stripped = _pfx_re.sub("", val).strip()
        if stripped != val:
            out[field] = stripped

    # ── AI-enriched boolean fields → Y/N display + XTRON SCORE ──────────────
    patch_bool = str(out.get("patch_available_bool") or "").strip().lower()
    if patch_bool == "true":
        out["patch_yn"] = "Y"
        out["patch_availability"] = "Yes"
    elif patch_bool == "false":
        out["patch_yn"] = "N"
        out["patch_availability"] = "No"
    else:
        # Fallback for non-AI-enriched rows: use patch_availability text
        pa = str(out.get("patch_availability") or "").strip().lower()
        out["patch_yn"] = "Y" if pa in ("yes", "true", "1") else ("N" if pa in ("no", "false", "0") else "")
        if out["patch_yn"] == "Y":
            out["patch_availability"] = "Yes"
        elif out["patch_yn"] == "N":
            out["patch_availability"] = "No"

    poc_bool = str(out.get("poc_available_bool") or "").strip().lower()
    if poc_bool == "true":
        out["poc_yn"] = "Y"
        out["poc_availability"] = "Yes"
    elif poc_bool == "false":
        out["poc_yn"] = "N"
        out["poc_availability"] = "No"
    else:
        # Fallback for non-AI-enriched rows: use poc_availability / kev_flag
        poc_pa = str(out.get("poc_availability") or "").strip().lower()
        kev    = str(out.get("kev_flag") or "").strip().lower()
        out["poc_yn"] = "Y" if poc_pa in ("yes", "true", "1") or kev in ("yes", "true", "1", "kev") else ("N" if poc_pa in ("no", "false", "0") else "")
        if out["poc_yn"] == "Y":
            out["poc_availability"] = "Yes"
        elif out["poc_yn"] == "N":
            out["poc_availability"] = "No"

    # XTRON SCORE: use stored DB value if enriched, else compute on-the-fly
    if out.get("xtron_score") is not None:
        try:
            out["xtron_score"] = int(out["xtron_score"])
        except (ValueError, TypeError):
            out["xtron_score"] = None
    if out.get("xtron_score") is None:
        # On-the-fly calculation for non-enriched rows
        sev_key = str(out.get("severity") or "").strip().lower()
        sev_pts = 65 if sev_key == "critical" else (60 if sev_key == "high" else (50 if sev_key == "medium" else (35 if sev_key == "low" else 0)))
        poc_pts = 10 if out.get("poc_yn") == "Y" else 0
        out["xtron_score"] = sev_pts + poc_pts if sev_pts else None

    return out


async def _get_ics_data(force: bool = False, schedule_sync: bool = True) -> List[Dict]:
    """
    Return cached ICS data, preferring SQLite database.
    - First tries SQLite (persistent, survives app restarts)
    - Falls back to memory cache (faster for repeated requests)
    - Only refetches from APIs if cache is stale AND SQLite needs updating
    - Uses LONG TTL (24 hours) to avoid repeated API calls
    """
    global _ics_cache, _ics_cache_ts, _ics_cache_key
    now = time.time()
    cache_key = "rapidapi+excel" if getattr(settings, "RAPIDAPI_KEY", "").strip() else "csv+excel"

    # Always serve cached data first. The monthly schedule only controls remote refreshes.
    if not force and _ics_cache and _ics_cache_key == cache_key and (now - _ics_cache_ts) < _ICS_MEMORY_CACHE_TTL:
        logger.debug("ICS Advisory: using fresh memory cache (%d rows, age %.0fs)", len(_ics_cache), now - _ics_cache_ts)
        return _ics_cache

    if not force and _db:
        try:
            db_result = await _db.get_ics_advisories(page_size=10000)
            if db_result and db_result.get("items"):
                rows = [_map_db_row_to_frontend(r) for r in db_result.get("items", [])]
                # Only serve the DB cache when we are not in the monthly refresh window.
                # On the 1st of the month, we intentionally bypass the DB cache to pull latest API data and upsert it.
                if not schedule_sync or not _should_run_ics_monthly_sync():
                    _ics_cache = rows
                    _ics_cache_ts = now
                    _ics_cache_key = cache_key
                    logger.info("ICS Advisory: loaded %d rows from SQLite (persistent cache)", len(rows))
                    return rows
                logger.info("ICS Advisory: monthly refresh window is active; fetching fresh API data to update SQLite cache")
        except Exception as e:
            logger.debug("ICS Advisory: SQLite read failed: %s, will fetch from API", e)

    if not force and schedule_sync and not _should_run_ics_monthly_sync():
        logger.info("ICS Advisory: skipping remote pull outside the monthly schedule (allowed only on day 1 of the month).")
        if _ics_cache:
            logger.debug("ICS Advisory: returning existing in-memory cache instead of remote fetch")
            return _ics_cache
        return []
    
    # SQLite doesn't have data or is unavailable — fetch from APIs
    logger.info("ICS Advisory: SQLite cache empty, fetching from APIs...")
    rapidapi_rows: List[Dict] = []
    if getattr(settings, "RAPIDAPI_KEY", "").strip():
        try:
            logger.info("ICS Advisory: fetching from RapidAPI...")
            rapidapi_rows = await _fetch_ics_rapidapi()
            logger.info("ICS Advisory: RapidAPI returned %d CVE rows", len(rapidapi_rows))
        except Exception as e:
            logger.warning("ICS Advisory RapidAPI fetch failed; falling back to CSV: %s", e)

    excel_rows: List[Dict] = []
    try:
        from connectors.excel_ingestion import fetch_excel_ics_rows
        excel_rows = await fetch_excel_ics_rows()
        logger.info("ICS Advisory: workbook Sheet3 returned %d CVE rows", len(excel_rows))
    except Exception as e:
        logger.warning("ICS Advisory workbook Sheet3 fetch failed: %s", e)

    logger.info("ICS Advisory: fetching CSV cache from GitHub...")
    try:
        csv_rows = await _fetch_ics_csv()
        data = _merge_ics_rows(rapidapi_rows, csv_rows) if rapidapi_rows else csv_rows
        if excel_rows:
            data = _merge_ics_rows(excel_rows, data)
        data.sort(
            key=lambda r: (
                r.get("published_year") or r.get("year") or 0,
                r.get("published_month") or r.get("month") or 0,
                str(r.get("release_date") or r.get("published_date") or r.get("last_updated") or ""),
            ),
            reverse=True,
        )
        _ics_cache = data
        _ics_cache_ts = now
        _ics_cache_key = cache_key
        logger.info("ICS Advisory: fetched %d rows from APIs and cached in memory", len(data))
        
        # Background task: sync to SQLite for persistence
        if _db and schedule_sync:
            asyncio.create_task(_sync_ics_advisories_to_db(force=False))
        
    except Exception as e:
        logger.error("ICS Advisory API fetch failed: %s", e)
        if rapidapi_rows or excel_rows:
            _ics_cache = _merge_ics_rows(excel_rows, rapidapi_rows) if excel_rows else rapidapi_rows
            _ics_cache_ts = now
            _ics_cache_key = cache_key
        elif _ics_cache:
            logger.warning("Using stale ICS cache (%d rows)", len(_ics_cache))
        else:
            raise HTTPException(503, f"ICS advisory data unavailable: {e}")
    return _ics_cache


# ── ICS Advisory SQLite Persistence ─────────────────────────────────────────

async def _sync_ics_advisories_to_db(force: bool = True) -> tuple[int, int]:
    """
    Fetch latest ICS data and persist to ics_advisories table.
    Returns (synced_count, new_count).
    """
    global _db

    if not force and not _should_run_ics_monthly_sync():
        logger.info("ICS Advisory: monthly sync skipped; allowed only on the 1st of the month.")
        return 0, 0
    
    # Ensure database is available
    if not _db:
        from database.db import Database
        _db = Database()
        await _db.initialize()
    
    try:
        logger.info("ICS Advisory: starting SQLite sync")
        # Always fetch fresh API rows during monthly sync so new advisories are upserted
        # without discarding the previously persisted database data.
        rows = await _get_ics_data(force=True, schedule_sync=False)

        if not rows:
            logger.info("ICS Advisory: no rows to sync")
            return 0, 0
        
        synced_count = 0
        new_count = 0
        for row in rows:
            try:
                # Map CSV field names to database schema names
                record = {
                    "ics_number": row.get("ics_number") or row.get("advisory_id") or "",
                    "cve_id": row.get("cve_id") or "N/A",
                    "title": row.get("title") or "",
                    "affected_vendor": row.get("affected_vendor") or "",  # Maps to 'vendor' in upsert
                    "affected_application": row.get("affected_application") or "",  # Maps to 'product'
                    "cvss_score": row.get("cvss_score") or "",
                    "cvss_severity": row.get("cvss_severity") or "medium",  # Maps to 'severity'
                    "release_date": row.get("release_date") or row.get("published_date") or "",
                    "last_updated": row.get("last_updated") or "",
                    "release_year": row.get("release_year") or row.get("published_year") or row.get("year"),
                    "release_month": row.get("release_month") or row.get("published_month") or row.get("month"),
                    "update_year": row.get("update_year"),
                    "update_month": row.get("update_month"),
                    "cve_year": row.get("cve_year") or _extract_cve_year(row.get("cve_id") or ""),
                    "advisory_url": row.get("advisory_url") or row.get("url") or "",
                    "sector": row.get("sector") or "",
                    "patch_availability": row.get("patch_availability") or "Unknown",
                    "poc_availability": row.get("poc_availability") or "Unknown",
                    "impact": row.get("impact") or "",
                    "affected_version": row.get("affected_version") or "",
                    "fixed_version": row.get("fixed_version") or "",
                    "cwe": row.get("cwe") or "",
                    "vendor_hq": row.get("vendor_hq") or "",
                    "product_distribution": row.get("product_distribution") or "",
                    "kev_flag": row.get("kev_flag") or "",
                    "data_source": row.get("data_source") or "csv",
                }
                _, is_new = await _db.upsert_ics_advisory(record)
                synced_count += 1
                if is_new:
                    new_count += 1
            except Exception as e:
                logger.debug("Failed to upsert ICS row %s: %s", row.get("ics_number"), e)
                continue
        
        logger.info("ICS Advisory: synced %d records to SQLite (%d new)", synced_count, new_count)
        return synced_count, new_count
    except Exception as e:
        logger.error("ICS Advisory sync failed: %s", e)
        return 0, 0


# ── ICS Advisory Endpoints ─────────────────────────────────────────────────

@advisory_router.get("/ics/meta")
async def ics_meta():
    """Return available years, months (with actual data), vendors and severities.
    Reads from SQLite database if available, falls back to memory cache."""
    # Try database first
    if _db:
        try:
            db_meta = await _db.get_ics_meta()
            if db_meta.get("total", 0) > 0:
                logger.debug("ICS meta from SQLite: %d total advisories", db_meta["total"])
                # Query distinct release_dates to extract years and months
                async with _db._conn.execute("SELECT DISTINCT release_date FROM ics_advisories WHERE release_date != ''") as cur:
                    db_dates = [r[0] for r in await cur.fetchall()]
                
                years_set = set()
                months_set = set()
                for dt_str in db_dates:
                    y, m = _parse_date(dt_str)
                    if y:
                        years_set.add(int(y))
                    if m:
                        months_set.add(int(m))
                
                years = db_meta.get("years") or sorted(years_set, reverse=True)
                month_nums_with_data = sorted(months_set)
                months_with_data = [(m, _MONTH_NAMES[m]) for m in month_nums_with_data if 1 <= m <= 12]
                
                vendors = db_meta.get("vendors", [])
                sevs = sorted({str(r.get("severity", "")).capitalize() for r in db_meta.get("by_severity", []) if r.get("severity", "")})
                
                # Check data sources
                async with _db._conn.execute("SELECT DISTINCT data_source FROM ics_advisories WHERE data_source != ''") as cur:
                    sources = sorted({r[0] for r in await cur.fetchall()})
                
                ai_available = bool(_ai and (
                    getattr(settings, "GROQ_API_KEY", "") or
                    getattr(settings, "OPENROUTER_API_KEY", "") or
                    getattr(settings, "ANTHROPIC_API_KEY", "")
                ))
                return {
                    "years":      years,
                    "months":     months_with_data,
                    "cve_pub_years": db_meta.get("cve_pub_years", []),
                    "cve_pub_months": db_meta.get("cve_pub_months", []),
                    "cvelist_enriched": db_meta.get("cvelist_enriched", 0),
                    "vendors":    vendors,
                    "severities": sevs,
                    "sources":    sources,
                    "ai_enrich_available": ai_available,
                    "filter_basis": {
                        "year": "ICS advisory published/release year",
                        "month": "ICS advisory published/release month",
                    },
                    "total_rows": db_meta.get("total", 0),
                    "source": "sqlite",
                }
        except Exception as e:
            logger.debug("ICS meta from SQLite failed: %s, falling back to cache", e)
    
    # Fallback to memory cache
    rows = await _get_ics_data()
    years   = sorted({(r.get("published_year") or r.get("year")) for r in rows if (r.get("published_year") or r.get("year"))}, reverse=True)
    vendors = sorted({r["affected_vendor"] for r in rows if r["affected_vendor"]})
    sevs    = sorted({r["cvss_severity"]   for r in rows if r["cvss_severity"]})
    source_set = set()
    for r in rows:
        for source in re.split(r"[+,]", str(r.get("data_source", "csv"))):
            source = source.strip()
            if source:
                source_set.add(source)
    sources = sorted(source_set)
    # Only return months that actually have data (fix month filter bug)
    month_nums_with_data = sorted({(r.get("published_month") or r.get("month")) for r in rows if (r.get("published_month") or r.get("month"))})
    months_with_data = [(m, _MONTH_NAMES[m]) for m in month_nums_with_data if 1 <= m <= 12]
    ai_available = bool(_ai and (
        getattr(settings, "GROQ_API_KEY", "") or
        getattr(settings, "OPENROUTER_API_KEY", "") or
        getattr(settings, "ANTHROPIC_API_KEY", "")
    ))
    return {
        "years":      years,
        "months":     months_with_data,   # Only months with real data
        "vendors":    vendors[:300],
        "severities": sevs,
        "sources":    sources,
        "ai_enrich_available": ai_available,
        "filter_basis": {
            "year": "ICS advisory published/release year",
            "month": "ICS advisory published/release month",
        },
        "total_rows": len(rows),
        "cached_at":  _ics_cache_ts,
        "source": "cache",
    }


@advisory_router.post("/ics/refresh")
async def ics_refresh():
    """Force-expire the ICS cache and sync fresh ICS data into SQLite."""
    global _ics_cache, _ics_cache_ts, _ics_cache_key, _ics_enrichment_cache
    _ics_cache = []
    _ics_cache_ts = 0.0
    _ics_cache_key = ""
    _ics_enrichment_cache = {}
    
    try:
        synced, new = await _sync_ics_advisories_to_db(force=True) if _db else (0, 0)
        logger.info("ICS cache cleared and refresh completed: %d records processed, %d new", synced, new)
        return {"status": "ok", "synced": synced, "new": new, "message": f"ICS data refreshed ({synced} records processed, {new} new)."}
    except Exception as e:
        logger.error("ICS Advisory manual refresh failed: %s", e)
        raise HTTPException(503, f"ICS refresh failed: {e}")


@advisory_router.post("/ics/sync")
async def ics_sync_now():
    """Manually sync latest ICS data into SQLite."""
    if not _db:
        raise HTTPException(503, "Database not available")
    synced, new = await _sync_ics_advisories_to_db(force=True)
    return {"status": "ok", "synced": synced, "new": new}


async def _fetch_advisory_page_text(url: str) -> str:
    if not url:
        return ""
    # Normalise URL: use correct CISA path for medical advisories (no trailing slash — CISA redirects to no-slash)
    url_lower = url.lower()
    if "/ics-advisories/icsma-" in url_lower:
        url = re.sub(
            r"(?i)/ics-advisories/(icsma-[^/]+)/?$",
            r"/ics-medical-advisories/\1",
            url,
        )
    else:
        url = url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            html = resp.text
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
                    tag.decompose()
                main = soup.find("main") or soup.find("article") or soup.find("body")
                text = main.get_text(" ", strip=True) if main else soup.get_text(" ", strip=True)
                text = re.sub(r"\s+", " ", text).strip()
            except Exception:
                text = re.sub(r"<[^>]+>", " ", html)
                text = re.sub(r"\s+", " ", text).strip()
            return text[:10000]
    except Exception as exc:
        logger.warning("ICS advisory page fetch failed for %s: %s", url, exc)
        return ""


async def _fetch_ics_web_context(row: Dict[str, Any]) -> List[Dict[str, str]]:
    cve_id = row.get("cve_id") or ""
    if not cve_id or cve_id == "N/A":
        return []
    try:
        from engine.web_search import search_cve
        results = await search_cve(cve_id)
    except Exception as exc:
        logger.debug("ICS CVE web search failed for %s: %s", cve_id, exc)
        return []
    cleaned = []
    seen = set()
    for item in results:
        url = str(item.get("url") or "").strip()
        title = str(item.get("title") or "").strip()
        snippet = str(item.get("snippet") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        cleaned.append({"title": title[:180], "url": url[:300], "snippet": snippet[:300]})
        if len(cleaned) >= 6:
            break
    return cleaned


def _web_context_text(results: List[Dict[str, str]]) -> str:
    if not results:
        return "(not available)"
    return "\n".join(
        f"- {r.get('title','')} | {r.get('url','')} | {r.get('snippet','')}"
        for r in results
    )


def _poc_from_web_context(cve_id: str, results: List[Dict[str, str]]) -> str:
    if not cve_id or not results:
        return "Unknown"
    cve = cve_id.lower()
    poc_terms = ("poc", "proof of concept", "exploit-db", "packetstorm", "metasploit", "github.com", "nuclei")
    for result in results:
        haystack = " ".join([result.get("title", ""), result.get("url", ""), result.get("snippet", "")]).lower()
        if cve in haystack and any(term in haystack for term in poc_terms):
            return "Yes (public PoC exists)"
    return "Unknown"


def _apply_deterministic_ics_context(row: Dict[str, Any], page_text: str, web_results: List[Dict[str, str]]) -> Dict[str, Any]:
    enriched = dict(row)
    text = page_text.lower()
    if _is_placeholder(enriched.get("patch_availability")):
        if any(term in text for term in ("has released an update", "recommends users update", "update to", "upgrade to", "fixed in", "patched in", "hotfix")):
            enriched["patch_availability"] = "Yes"
        elif any(term in text for term in ("no fix", "no patch", "will not fix", "no update available")):
            enriched["patch_availability"] = "No"
    if _is_placeholder(enriched.get("poc_availability")):
        enriched["poc_availability"] = _poc_from_web_context(enriched.get("cve_id", ""), web_results)
    if _is_placeholder(enriched.get("impact")) and not _is_placeholder(enriched.get("cwe")):
        enriched["impact"] = _cwe_to_impact(enriched.get("cwe", ""))
    if _is_placeholder(enriched.get("fixed_version")):
        for pattern in [
            r"(?i)(?:fixed in|patched in|resolved in|update to|upgrade to|upgrade to version|update to version|available in)\s+(?:version\s+)?([A-Za-z0-9_.\-+/:]+)",
            r"(?i)(?:prior to|before|less than|earlier than|older than|under)\s*(?:v(?:ersion)?\s*)?([A-Za-z0-9_.\-+/:]+)",
            r"(?i)(?:version|v)\s*([0-9][A-Za-z0-9_.\-+]*)\s*(?:and later|or later|or newer|and newer)",
            r"(?i)(?:<|<=)\s*v?([A-Za-z0-9_.\-+/:]+)",
        ]:
            match = re.search(pattern, page_text)
            if match:
                enriched["fixed_version"] = match.group(1)[:80]
                break
    if _is_placeholder(enriched.get("fixed_version")) and not _is_placeholder(enriched.get("affected_version")):
        hint = _derive_fixed_version_hint(enriched.get("affected_version"))
        if not _is_placeholder(hint):
            enriched["fixed_version"] = hint
    return enriched


def _should_enrich_ics_row(row: Dict[str, Any]) -> bool:
    """Return True if any key field is missing/unknown/See Advisory."""
    if not row:
        return False
    for key in ("patch_availability", "poc_availability", "affected_version", "fixed_version", "impact"):
        if _is_placeholder(row.get(key)):
            return True
    return False


async def _enrich_single_ics_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich a single ICS row using CISA text, web-search evidence and AI."""
    cache_key = "|".join([
        str(row.get("ics_number") or row.get("advisory_id") or ""),
        str(row.get("cve_id") or ""),
        str(row.get("last_updated") or row.get("published_date") or row.get("release_date") or ""),
    ])
    if cache_key in _ics_enrichment_cache:
        return {**row, **_ics_enrichment_cache[cache_key]}
    page_text = await _fetch_advisory_page_text(row.get("advisory_url") or row.get("url") or "")
    web_results = await _fetch_ics_web_context(row)
    source_enriched = _apply_deterministic_ics_context(row, page_text, web_results)
    if not _ai:
        _ics_enrichment_cache[cache_key] = {k: v for k, v in source_enriched.items() if k not in row or row.get(k) != v}
        if _db:
            try:
                await _db.upsert_ics_advisory(source_enriched)
            except Exception as e:
                logger.warning("Failed to save deterministic enriched ICS row: %s", e)
        return source_enriched

    prompt = _build_ics_enrichment_prompt(source_enriched, page_text, web_results)
    try:
        analysis = await _ai.chat(prompt)
    except Exception as exc:
        logger.warning("ICS AI enrichment failed for %s: %s", row.get("cve_id"), exc)
        _ics_enrichment_cache[cache_key] = {k: v for k, v in source_enriched.items() if k not in row or row.get(k) != v}
        if _db:
            try:
                await _db.upsert_ics_advisory(source_enriched)
            except Exception as e:
                logger.warning("Failed to save deterministic enriched ICS row: %s", e)
        return source_enriched
    final_row = _apply_enrichment_to_row(source_enriched, analysis)
    _ics_enrichment_cache[cache_key] = {
        k: v for k, v in final_row.items()
        if k not in row or row.get(k) != v
    }
    if _db:
        try:
            await _db.upsert_ics_advisory(final_row)
        except Exception as e:
            logger.warning("Failed to save AI enriched ICS row: %s", e)
    return final_row


def _apply_enrichment_to_row(row: Dict[str, Any], analysis: str) -> Dict[str, Any]:
    """Parse the AI response lines and merge into the row dict."""
    def current(key: str) -> str:
        return "Unknown" if _is_placeholder(row.get(key)) else row.get(key)

    enriched = {
        "patch_availability": current("patch_availability"),
        "poc_availability":   current("poc_availability"),
        "affected_version":   current("affected_version"),
        "fixed_version":      current("fixed_version"),
        "impact":             current("impact"),
        "ai_enrichment":      analysis,
    }
    for line in analysis.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key   = key.strip().lower()
        value = value.strip()
        if _is_placeholder(value):
            continue
        if key == "patch availability":
            enriched["patch_availability"] = value
        elif key == "poc availability":
            enriched["poc_availability"] = value
        elif key == "affected version":
            enriched["affected_version"] = value
        elif key == "fixed version":
            enriched["fixed_version"] = value
        elif key == "impact":
            enriched["impact"] = value
        elif key in ("short summary", "summary"):
            enriched["short_summary"] = value
    return {**row, **enriched}


async def _enrich_ics_rows(rows: list) -> list:
    """Batch enrich up to 15 rows that need enrichment."""
    if not _ai:
        return rows
    sem = asyncio.Semaphore(4)

    async def enrich_row(row: Dict[str, Any]) -> Dict[str, Any]:
        if not _should_enrich_ics_row(row):
            return row
        async with sem:
            return await _enrich_single_ics_row(row)

    to_enrich  = rows[:min(len(rows), 15)]
    rest       = rows[len(to_enrich):]
    enriched   = list(await asyncio.gather(*(enrich_row(r) for r in to_enrich)))
    return enriched + rest


def _build_ics_enrichment_prompt(row: Dict[str, Any], page_text: str, web_results: Optional[List[Dict[str, str]]] = None) -> str:
    advisory_url = row.get("advisory_url") or row.get("url") or ""
    cve_id       = row.get("cve_id") or "N/A"
    advisory_id  = row.get("ics_number") or row.get("advisory_id") or "N/A"
    title        = row.get("title") or "N/A"
    published    = row.get("published_date") or row.get("release_date") or row.get("last_updated") or ""
    vendor       = row.get("affected_vendor") or ""
    product      = row.get("affected_application") or ""
    cwe          = row.get("cwe") or ""
    cvss         = row.get("cvss_score") or ""

    # Build a rich prompt that includes all available metadata so Groq can reason accurately
    web_context = _web_context_text(web_results or [])
    return f"""You are an expert ICS/OT cyber security analyst with access to CISA ICS-CERT advisory data.
Your task: fill in missing or placeholder fields for the ICS advisory below using the CISA advisory text and web-search evidence provided.
Do NOT guess. Use ONLY the supplied CISA text and exact-CVE search evidence.
If a field genuinely cannot be determined, write exactly: Unknown

Advisory ID   : {advisory_id}
CVE ID        : {cve_id}
Title         : {title}
Published     : {published}
Vendor        : {vendor}
Product       : {product}
CWE           : {cwe}
CVSS Score    : {cvss}
Advisory URL  : {advisory_url}

Current (possibly incomplete) field values:
  Patch Availability : {row.get('patch_availability') or 'Unknown'}
  POC Availability   : {row.get('poc_availability')   or 'Unknown'}
  Affected Version   : {row.get('affected_version')   or 'Unknown'}
  Fixed Version      : {row.get('fixed_version')      or 'Unknown'}
  Impact             : {row.get('impact')             or 'Unknown'}

Advisory page text (may be truncated):
---
{page_text[:5000] if page_text else '(not available)'}
---

Web-search evidence for this CVE (title | URL | snippet):
---
{web_context}
---

Rules:
- Patch Availability is Yes only when vendor/CISA text says a patch, upgrade, update, hotfix, or fixed version exists.
- POC Availability is Yes only when the supplied evidence references a public PoC/exploit for the exact CVE ID.
- Fixed Version must be a specific version/range from the supplied text; otherwise Unknown.
- Impact must be a concise technical impact, not "See Advisory".

Respond ONLY with these exact lines (no extra text, no markdown):
Patch Availability: [Yes / No / Unknown]
POC Availability: [Yes (public PoC exists) / No / Unknown]
Affected Version: [specific version range or Unknown]
Fixed Version: [specific fixed version or Unknown]
Impact: [concise impact description, e.g. Remote Code Execution, or Unknown]
Short Summary: [1-2 sentence plain-English summary of the vulnerability]
"""


@advisory_router.post("/ics/enrich")
async def ics_enrich(advisory_id: Optional[str] = Query(None), cve_id: Optional[str] = Query(None)):
    """Enrich missing ICS CVE advisory fields using the configured AI engine."""
    if not _ai:
        raise HTTPException(503, "AI engine not ready")
    if not advisory_id and not cve_id:
        raise HTTPException(400, "Provide advisory_id or cve_id to enrich")

    rows = await _get_ics_data()
    candidates = [r for r in rows if (
        (advisory_id and str(r.get('ics_number') or r.get('advisory_id') or '').lower() == advisory_id.lower())
        or (cve_id and str(r.get('cve_id') or '').lower() == cve_id.lower())
    )]
    if not candidates:
        raise HTTPException(404, "ICS advisory row not found")

    row = candidates[0]
    row_enriched = await _enrich_single_ics_row(row)
    return {
        'advisory_id': advisory_id or row_enriched.get('ics_number'),
        'cve_id': cve_id or row_enriched.get('cve_id'),
        'enriched_row': row_enriched,
        'analysis': row_enriched.get('ai_enrichment', ''),
    }


@advisory_router.get("/ics")
async def ics_advisories(
    year:     Optional[int] = Query(None, description="Filter by advisory release year (e.g. 2026)"),
    month:    Optional[int] = Query(None, ge=1, le=12, description="Filter by ICS advisory release month number (1-12)"),
    vendor:   Optional[str] = Query(None, description="Partial vendor name match"),
    severity: Optional[str] = Query(None, description="Critical / High / Medium / Low"),
    search:   Optional[str] = Query(None, description="Full-text search across CVE ID, title, vendor"),
    enrich:   bool          = Query(False, description="Use AI to enrich missing patch/POC/fixed/impact fields for returned rows"),
    filter_mode: str        = Query("advisory", description="'advisory' or 'cve_published'"),
    page:     int           = Query(1, ge=1),
    page_size: int          = Query(100, ge=1, le=500),
):
    """
    ICS Advisory CVE listing from the CISA ICS Advisory Project dataset.
    Reads from SQLite database if available, falls back to memory cache.
    Filterable by advisory release year/month, vendor, severity, and free-text search.

    NOTE: year and month filters apply to the ICS advisory RELEASE DATE, NOT the
    CVE-ID year. An advisory released in July 2026 may legitimately contain CVEs
    from older years (e.g. CVE-2021-41617) — this is expected and correct.

    GUARANTEES: Always returns valid JSON (never 500 error).
    """
    try:
        # Try to read from database first
        if _db:
            try:
                result = await _db.get_ics_advisories(
                    page=page, page_size=page_size,
                    year=year, month=month, vendor=vendor,
                    severity=severity, search=search, cve_id=search,
                    filter_mode=filter_mode
                )
                
                # Handle any query errors
                if result.get("error"):
                    logger.warning("ICS SQLite query error: %s, falling back to cache", result.get("error"))
                else:
                    # Success - map and enrich if needed
                    logger.debug("ICS advisories from SQLite: %d total", result.get("total", 0))
                    
                    # Map DB columns back to frontend expected keys
                    if result.get("items"):
                        result["items"] = [_map_db_row_to_frontend(r) for r in result["items"]]
                        
                    result["source"] = "sqlite"
                    return result
            except Exception as e:
                logger.warning("ICS read from SQLite failed: %s, falling back to cache", e)
        
        # Fallback to memory cache when SQLite unavailable or fails
        try:
            rows = await _get_ics_data()
        except Exception as e:
            logger.error("ICS data fetch failed completely: %s", e)
            return {
                "total": 0, "page": page, "page_size": page_size, "items": [],
                "source": "error",
                "error": str(e),
                "message": "Could not fetch ICS advisories from any source"
            }

        # Apply filters to memory cache — MUST use advisory release_year/release_month
        # to match the SQLite path. Both paths must be consistent.
        # NOTE: An advisory released in July 2026 can contain CVEs from any year.
        if year:
            rows = [
                r for r in rows
                if (r.get("release_year") or r.get("published_year") or r.get("year")) == year
            ]
        if month:
            rows = [
                r for r in rows
                if (r.get("release_month") or r.get("published_month") or r.get("month")) == month
            ]
        if vendor:
            vl = str(vendor).strip().lower() if vendor else ""
            if vl:
                rows = [r for r in rows if vl in (r.get("affected_vendor") or "").lower()]
        
        if severity:
            sl = str(severity).strip().lower() if severity else ""
            if sl:
                rows = [r for r in rows if (r.get("cvss_severity") or "").lower() == sl]
        
        if search:
            sl = str(search).strip().lower() if search else ""
            if sl:
                rows = [
                    r for r in rows
                    if sl in (r.get("cve_id") or "").lower()
                    or sl in (r.get("title") or "").lower()
                    or sl in (r.get("affected_vendor") or "").lower()
                    or sl in (r.get("affected_application") or "").lower()
                    or sl in (r.get("ics_number") or "").lower()
            ]

        # Sort results
        rows.sort(
            key=lambda r: (
                r.get("published_year") or r.get("year") or 0,
                r.get("published_month") or r.get("month") or 0,
                str(r.get("release_date") or r.get("published_date") or r.get("last_updated") or ""),
                r.get("ics_number") or "",
            ),
            reverse=True,
        )

        # Paginate
        total = len(rows)
        offset = (page - 1) * page_size
        page_rows = rows[offset: offset + page_size]
        
        # NOTE: AI enrichment disabled for ICS endpoint due to timeout issues (HTTP calls to CISA + AI APIs)
        # To re-enable, uncomment block below. Use background job queue instead for production.
        # if enrich and _ai:
        #     try:
        #         page_rows = await _enrich_ics_rows(page_rows)
        #     except Exception as enrich_err:
        #         logger.warning("ICS enrichment failed (cache path), returning unenriched data: %s", enrich_err)

        return {
            "total":     total,
            "page":      page,
            "page_size": page_size,
            "filter_basis": {
                "year": "CVE-ID year",
                "month": "ICS advisory published/release month",
            },
            "items":     page_rows,
            "source":    "cache",
        }
    
    except Exception as outer_err:
        logger.error("Unexpected error in ics_advisories endpoint: %s", outer_err, exc_info=True)
        return {
            "total": 0, "page": page, "page_size": page_size, "items": [],
            "source": "error",
            "error": str(outer_err),
            "message": "Unexpected system error — please try again"
        }


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


async def init_ics_advisory_system() -> None:
    """
    Initialize ICS advisory system on startup.
    - Syncs ICS data from RapidAPI/CSV to SQLite database
    - Sets up cached memory to avoid repeated API calls
    - Should be called once during app startup
    """
    global _ics_db_synced
    
    if not _db:
        logger.warning("ICS advisory init: database not available yet")
        return
    
    async with _ics_sync_lock:
        if _ics_db_synced:
            logger.debug("ICS advisory: already initialized")
            _ensure_nvd_enrichment_task()
            return
        
        try:
            logger.info("ICS Advisory: initializing on startup...")

            # Always load and serve SQLite cache first. Only month-1 triggers a remote API refresh.
            try:
                meta = await _db.get_ics_meta()
                if meta.get("total", 0) > 0:
                    max_updated = await _db._query_val("SELECT MAX(updated_at) FROM ics_advisories")
                    is_fresh = False
                    if max_updated:
                        try:
                            parsed = datetime.fromisoformat(str(max_updated).replace("Z", "+00:00"))
                            is_fresh = (datetime.now(parsed.tzinfo) - parsed).total_seconds() < _ICS_DB_CACHE_TTL
                        except Exception:
                            try:
                                parsed = datetime.strptime(str(max_updated)[:19], "%Y-%m-%d %H:%M:%S")
                                is_fresh = (datetime.utcnow() - parsed).total_seconds() < _ICS_DB_CACHE_TTL
                            except Exception:
                                is_fresh = False

                    if is_fresh:
                        try:
                            fixed_updates = await _db.backfill_ics_fixed_versions()
                            if fixed_updates:
                                logger.info("ICS Advisory: backfilled %d fixed-version values from affected-version text", fixed_updates)
                        except Exception as backfill_err:
                            logger.debug("ICS Advisory: fixed-version backfill skipped: %s", backfill_err)
                        logger.info("ICS Advisory: found %d fresh advisories in SQLite (using cached data)", meta.get("total", 0))
                        _ics_db_synced = True
                        _ensure_nvd_enrichment_task()
                        return

                    if not _should_run_ics_monthly_sync():
                        logger.info("ICS Advisory: SQLite cache exists but it is not the 1st of the month; serving cached data without remote sync.")
                        _ics_db_synced = True
                        _ensure_nvd_enrichment_task()
                        return
                    logger.info(
                        "ICS Advisory: SQLite cache stale (fresh=%s); syncing",
                        is_fresh
                    )
            except Exception as e:
                logger.debug("ICS Advisory: SQLite check failed: %s", e)

            # Sync ICS data to SQLite only on the 1st of the month; otherwise serve the cache.
            logger.info("ICS Advisory: syncing data from APIs to SQLite...")
            synced_count, new_count = await _sync_ics_advisories_to_db()
            
            if synced_count > 0:
                logger.info(
                    "ICS Advisory: synced %d advisories to SQLite on startup (%d new)",
                    synced_count,
                    new_count,
                )
            else:
                logger.warning("ICS Advisory: sync completed but no new advisories (may already be cached)")

            try:
                fixed_updates = await _db.backfill_ics_fixed_versions()
                if fixed_updates:
                    logger.info("ICS Advisory: backfilled %d fixed-version values from affected-version text", fixed_updates)
            except Exception as backfill_err:
                logger.debug("ICS Advisory: fixed-version backfill skipped after sync: %s", backfill_err)
            
            _ics_db_synced = True
            logger.info("ICS Advisory: initialization complete — queries will use SQLite cache")
            
            _ensure_nvd_enrichment_task()
            
        except Exception as e:
            logger.error("ICS Advisory init error: %s", e)
            _ics_db_synced = True  # Mark as attempted even if failed


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
    hours:        str           = Query("168"),
):
    """List advisories with filters. Default: last 7 days."""
    val = hours
    if val != "today":
        try:
            val = int(hours)
        except ValueError:
            val = 168
    return await _db.get_advisories(
        page=page, page_size=page_size, company=company,
        severity=severity, category=category,
        advisory_type=advisory_type, search=search, hours=val,
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
async def critical_advisories(hours: str = Query("72")):
    """Get only critical severity advisories."""
    val = hours
    if val != "today":
        try:
            val = int(hours)
        except ValueError:
            val = 72
    return await _db.get_advisories(severity="critical", hours=val, page_size=100)


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
        except Exception: pass

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

**Mapped Internal IOCs (ThreatIntel DB):**
{mapped_ioc_lines}

**Mapped Related Victims (ThreatIntel DB):**
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
    ThreatIntel FinalFeed Core Monitoring report.
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

    prompt = f"""Generate a ThreatIntel FinalFeed Core Threat Monitoring report.

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

== SECTION 1 — ThreatIntel FinalFeed Core Threat Monitoring ==

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
