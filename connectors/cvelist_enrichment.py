"""
connectors/cvelist_enrichment.py

Enriches ICS advisory CVE rows with official publish dates from the
CVEProject/cvelistV5 GitHub repo.

Two modes:
  ① One-time bulk enrichment from local zip
     build_cvelist_index(zip_path)  →  run_cvelist_enrichment_loop(db, index)
     Used at startup to fill historical data from the downloaded cvelistV5.zip.

  ② Live 5-minute GitHub polling
     run_cvelist_live_sync_loop(db)
     Calls the GitHub Commits API every 5 minutes, detects changed CVE JSON
     files, fetches only those files from raw.githubusercontent.com, and
     updates any matching rows in ics_advisories.  Also re-enriches any
     rows whose cvelist_status is still 'pending' (newly synced ICS rows).

Fields written to ics_advisories:
  - cve_published_date  (ISO 8601 string)
  - cve_pub_year        (int)
  - cve_pub_month       (int)
  - cve_updated_date    (ISO 8601 string)
  - cvelist_status      'done' | 'not_found'
"""

import asyncio
import json
import logging
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# GitHub repo details
_GH_API_BASE  = "https://api.github.com/repos/CVEProject/cvelistV5"
_GH_RAW_BASE  = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
_POLL_INTERVAL_SECS = 300   # 5 minutes
_HTTP_TIMEOUT       = 20.0  # seconds

_VENDOR_HQ_BY_NAME = {
    "fortinet": "United States",
    "milestone systems": "Denmark",
    "red hat": "United States",
    "furuno electric co., ltd.": "Japan",
    "furuno electric co.,ltd.": "Japan",
    "atn-b1": "Global",
}

_CWE_IMPACT = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-23": "Relative Path Traversal",
    "CWE-35": "Path Traversal",
    "CWE-59": "Link Following",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Stack Buffer Overflow",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure",
    "CWE-255": "Credentials Management",
    "CWE-256": "Cleartext Storage of Password",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-294": "Authentication Bypass by Capture-replay",
    "CWE-295": "Certificate Validation Failure",
    "CWE-306": "Missing Authentication",
    "CWE-312": "Cleartext Storage of Sensitive Info",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken Crypto Algorithm",
    "CWE-330": "Insufficient Randomness",
    "CWE-345": "Insufficient Verification",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "CSRF",
    "CWE-362": "Race Condition",
    "CWE-400": "Resource Exhaustion / DoS",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficient Credential Protection",
    "CWE-601": "Open Redirect",
    "CWE-611": "XXE Injection",
    "CWE-639": "Authorization Bypass",
    "CWE-640": "Weak Password Recovery",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-749": "Dangerous Method Exposure",
    "CWE-770": "Resource Allocation Without Limits",
    "CWE-787": "Out-of-Bounds Write / RCE",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-916": "Weak Password Hash",
    "CWE-918": "SSRF",
}


# ── Data class ─────────────────────────────────────────────────────────────────

@dataclass
class CveEntry:
    cve_id: str
    state: str = ""
    date_published: str = ""    # ISO 8601
    date_updated: str = ""
    pub_year: Optional[int] = None
    pub_month: Optional[int] = None
    vendor: str = ""
    product: str = ""
    affected_version: str = ""
    fixed_version: str = ""
    cvss_score: str = ""
    cvss_severity: str = ""
    cwe: str = ""
    description: str = ""
    title: str = ""
    impact: str = ""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_iso_date(s: str) -> Tuple[Optional[int], Optional[int]]:
    """Return (year, month) ints from an ISO 8601 string, or (None, None)."""
    if not s:
        return None, None
    m = re.match(r"(\d{4})-(\d{2})", s.strip())
    if m:
        return int(m.group(1)), int(m.group(2))
    return None, None


def _first_english_text(items: List[dict], key: str = "value") -> str:
    for item in items or []:
        if str(item.get("lang") or "").lower().startswith("en"):
            return str(item.get(key) or "").strip()
    if items:
        return str(items[0].get(key) or "").strip()
    return ""


def _uniq(values: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _short(text: str, limit: int = 500) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[: limit - 1] + "..." if len(text) > limit else text


def _is_affected_item(item: dict) -> bool:
    default_status = str(item.get("defaultStatus") or "").strip().lower()
    versions = item.get("versions") or []
    if any(str(v.get("status") or "").strip().lower() == "affected" for v in versions):
        return True
    if default_status == "affected":
        return True
    if default_status == "unaffected" and versions:
        return False
    return bool(item.get("vendor") or item.get("product"))


def _format_version_range(product: str, version: dict, default_status: str) -> Tuple[str, str]:
    status = str(version.get("status") or "").strip().lower()
    start = str(version.get("version") or "").strip()
    less_than = str(version.get("lessThan") or "").strip()
    less_equal = str(version.get("lessThanOrEqual") or "").strip()
    product = product or "Product"

    affected = ""
    fixed = ""
    if status == "affected":
        if less_than and less_than != "*":
            affected = f"{product} {start} before {less_than}" if start and start != "0" else f"{product} before {less_than}"
            fixed = f"{product} {less_than} or later"
        elif less_equal and less_equal != "*":
            affected = f"{product} {start} through {less_equal}" if start and start != "0" else f"{product} through {less_equal}"
        elif start and start.lower() not in {"0", "*", "unspecified", "unknown"}:
            affected = f"{product} {start}"
        else:
            affected = product
    elif status == "unaffected" and default_status == "affected" and start and start != "*":
        fixed = f"{product} {start} or later"

    return affected, fixed


def _extract_affected_summary(cna: dict) -> Tuple[str, str, str, str]:
    affected_items = [a for a in (cna.get("affected") or []) if _is_affected_item(a)]
    if not affected_items and cna.get("affected"):
        affected_items = [cna["affected"][0]]
    if not affected_items:
        return "", "", "", ""

    primary_vendor = str(affected_items[0].get("vendor") or "").strip()
    same_vendor_items = [
        a for a in affected_items
        if str(a.get("vendor") or "").strip().lower() == primary_vendor.lower()
    ] or affected_items

    products = _uniq([str(a.get("product") or "").strip() for a in same_vendor_items])
    product_display = "; ".join(products[:4])
    if len(products) > 4:
        product_display = f"{product_display}; +{len(products) - 4} more"

    affected_parts: List[str] = []
    fixed_parts: List[str] = []
    for item in same_vendor_items[:8]:
        product = str(item.get("product") or "").strip()
        default_status = str(item.get("defaultStatus") or "").strip().lower()
        versions = item.get("versions") or []
        if not versions and default_status == "affected":
            affected_parts.append(f"{product}: affected versions" if product else "Affected versions")
            continue
        for version in versions[:12]:
            affected, fixed = _format_version_range(product, version, default_status)
            if affected:
                affected_parts.append(affected)
            if fixed:
                fixed_parts.append(fixed)

    return (
        primary_vendor,
        product_display,
        _short("; ".join(_uniq(affected_parts))),
        _short("; ".join(_uniq(fixed_parts)), limit=300),
    )


def _extract_cvss(cna: dict) -> Tuple[str, str]:
    metrics = cna.get("metrics") or []
    # Prefer CVSS 3.x when both 3.x and 4.0 are published; the existing UI and
    # severity expectations are based on CVSS 3.1 for these advisory tables.
    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
        for metric in metrics:
            cvss = metric.get(key)
            if not isinstance(cvss, dict):
                continue
            score = cvss.get("baseScore")
            if score in (None, ""):
                continue
            severity = str(cvss.get("baseSeverity") or "").strip().capitalize()
            return str(score), severity
    return "", ""


def _extract_cwe(cna: dict) -> str:
    cwes: List[str] = []
    for problem in cna.get("problemTypes") or []:
        for desc in problem.get("descriptions") or []:
            cwe = str(desc.get("cweId") or "").strip()
            if cwe.upper().startswith("CWE-"):
                cwes.append(cwe.upper())
    return ", ".join(_uniq(cwes))


def _impact_from_cwe(cwe: str) -> str:
    impacts = []
    for item in re.split(r"[,;]\s*", cwe or ""):
        label = _CWE_IMPACT.get(item.strip().upper())
        if label and label not in impacts:
            impacts.append(label)
    return ", ".join(impacts)


def _title_from_cve(product: str, cwe: str, description: str) -> str:
    impact = _impact_from_cwe(cwe)
    if impact and product:
        return _short(f"{impact} in {product}", limit=120)
    if impact:
        return _short(impact, limit=120)
    first_sentence = re.split(r"(?<=[.!?])\s+", description or "", maxsplit=1)[0]
    return _short(first_sentence, limit=120)


def _entry_from_json(data: dict) -> Optional[CveEntry]:
    """Parse a CVE JSON dict and return a CveEntry, or None on bad data."""
    meta = data.get("cveMetadata") or {}
    cve_id = str(meta.get("cveId") or "").strip().upper()
    if not cve_id or not CVE_ID_RE.match(cve_id):
        return None
    date_pub = str(meta.get("datePublished") or "").strip()
    date_upd = str(meta.get("dateUpdated") or "").strip()
    state    = str(meta.get("state") or "").strip()
    year, month = _parse_iso_date(date_pub)
    cna = (data.get("containers") or {}).get("cna") or {}
    vendor, product, affected_version, fixed_version = _extract_affected_summary(cna)
    cvss_score, cvss_severity = _extract_cvss(cna)
    cwe = _extract_cwe(cna)
    description = _first_english_text(cna.get("descriptions") or [])
    impact = _impact_from_cwe(cwe)
    return CveEntry(
        cve_id=cve_id,
        state=state,
        date_published=date_pub,
        date_updated=date_upd,
        pub_year=year,
        pub_month=month,
        vendor=vendor,
        product=product,
        affected_version=affected_version,
        fixed_version=fixed_version,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        cwe=cwe,
        description=_short(description, limit=1000),
        title=_title_from_cve(product, cwe, description),
        impact=impact,
    )


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _json_dict(value: Any) -> dict:
    if isinstance(value, dict):
        return dict(value)
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _merge_official_blob(blob: Any, entry: CveEntry) -> str:
    data = _json_dict(blob)
    vendor_hq = _VENDOR_HQ_BY_NAME.get(entry.vendor.lower(), "")
    updates = {
        "cvelist_official": True,
        "cvelist_source": "CVEProject/cvelistV5",
        "cve_published_date": entry.date_published,
        "cve_updated_date": entry.date_updated,
        "cve_pub_year": entry.pub_year,
        "cve_pub_month": entry.pub_month,
        "affected_vendor": entry.vendor,
        "affected_application": entry.product,
        "vendor": entry.vendor,
        "product": entry.product,
        "cvss_score": entry.cvss_score,
        "cvss_severity": entry.cvss_severity,
        "severity": entry.cvss_severity.lower() if entry.cvss_severity else "",
        "cwe": entry.cwe,
        "cve_description": entry.description,
        "title": entry.title,
        "impact": entry.impact,
    }
    if vendor_hq:
        updates["vendor_hq"] = vendor_hq
    if entry.affected_version:
        updates["affected_version"] = entry.affected_version
    if entry.fixed_version:
        updates["fixed_version"] = entry.fixed_version

    for key, value in updates.items():
        if value not in (None, ""):
            data[key] = value
    return json.dumps(data)


async def _apply_entry(db, row_id: int, entry: CveEntry) -> None:
    async with db._conn.execute(
        "SELECT raw_data, normalized_data, ai_enriched FROM ics_advisories WHERE id=?",
        (row_id,),
    ) as cur:
        row = await cur.fetchone()
    raw_data = _merge_official_blob(row["raw_data"] if row else "{}", entry)
    normalized_data = _merge_official_blob(row["normalized_data"] if row else "{}", entry)
    severity = entry.cvss_severity.lower() if entry.cvss_severity else ""
    vendor_hq = _VENDOR_HQ_BY_NAME.get(entry.vendor.lower(), "")

    await db._conn.execute(
        """UPDATE ics_advisories
           SET cve_published_date = ?,
               cve_updated_date   = ?,
               cve_pub_year       = ?,
               cve_pub_month      = ?,
               title              = CASE WHEN COALESCE(ai_enriched, 0) = 1 THEN title ELSE COALESCE(NULLIF(?, ''), title) END,
               impact             = CASE WHEN COALESCE(ai_enriched, 0) = 1 THEN impact ELSE COALESCE(NULLIF(?, ''), impact) END,
               affected_version   = CASE WHEN COALESCE(ai_enriched, 0) = 1 THEN affected_version ELSE COALESCE(NULLIF(?, ''), affected_version) END,
               fixed_version      = CASE WHEN COALESCE(ai_enriched, 0) = 1 THEN fixed_version ELSE COALESCE(NULLIF(?, ''), fixed_version) END,
               cvss_score         = COALESCE(NULLIF(?, ''), cvss_score),
               severity           = COALESCE(NULLIF(?, ''), severity),
               cwe                = COALESCE(NULLIF(?, ''), cwe),
               raw_data           = ?,
               normalized_data    = ?,
               cvelist_status     = 'done'
           WHERE id = ?""",
        (entry.date_published, entry.date_updated,
         entry.pub_year, entry.pub_month,
         entry.title, entry.impact,
         entry.affected_version, entry.fixed_version,
         entry.cvss_score, severity, entry.cwe,
         raw_data, normalized_data, row_id),
    )


async def _apply_by_cve_id(db, cve_id: str, entry: CveEntry) -> int:
    """Update all ICS rows matching cve_id. Returns number of rows updated."""
    async with db._conn.execute(
        "SELECT id FROM ics_advisories WHERE UPPER(TRIM(cve_id)) = ?",
        (cve_id,),
    ) as cur:
        rows = await cur.fetchall()
    for row in rows:
        await _apply_entry(db, row["id"], entry)
    return len(rows)


async def _mark_not_found(db, row_id: int) -> None:
    await db._conn.execute(
        "UPDATE ics_advisories SET cvelist_status='not_found' WHERE id=?",
        (row_id,),
    )


async def _fetch_pending(db, batch_size: int) -> list:
    """Return ICS rows still needing CVEList enrichment."""
    async with db._conn.execute(
        """SELECT id, cve_id FROM ics_advisories
           WHERE (
                cvelist_status IS NULL
                OR cvelist_status = 'pending'
                OR (
                    cvelist_status = 'done'
                    AND (normalized_data IS NULL OR normalized_data NOT LIKE '%"cvelist_official": true%')
                )
           )
             AND cve_id IS NOT NULL
             AND TRIM(UPPER(cve_id)) NOT IN ('N/A', 'NONE', '')
           LIMIT ?""",
        (batch_size,),
    ) as cur:
        return await cur.fetchall()


async def _cve_exists_in_db(db, cve_id: str) -> bool:
    """True if at least one ICS advisory row has this CVE-ID."""
    async with db._conn.execute(
        "SELECT 1 FROM ics_advisories WHERE UPPER(TRIM(cve_id)) = ? LIMIT 1",
        (cve_id,),
    ) as cur:
        return bool(await cur.fetchone())


# ── ① Bulk zip enrichment (startup) ───────────────────────────────────────────

_GH_ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"


async def download_and_build_cvelist_index(
    github_token: Optional[str] = None,
) -> Dict[str, CveEntry]:
    """
    Download cvelistV5 zip directly from GitHub into memory and build the index.
    This avoids needing cvelistV5.zip committed to git or on disk at all.
    Falls back to the live-per-CVE approach if the download fails.
    """
    import io as _io
    headers = {
        "User-Agent": "ThreatIntel-TIP/1.0",
        "Accept": "application/vnd.github+json",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    logger.info("[CVEList] Downloading cvelistV5 archive from GitHub (this may take ~2-3 min)…")
    try:
        async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
            resp = await client.get(_GH_ZIP_URL, headers=headers)
            if resp.status_code != 200:
                logger.warning("[CVEList] ZIP download failed: HTTP %d", resp.status_code)
                return {}
            data = resp.content

        logger.info("[CVEList] Downloaded %d MB — parsing…", len(data) // 1024 // 1024)
        index: Dict[str, CveEntry] = {}
        count = errors = 0
        buf = _io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            for name in zf.namelist():
                if not (name.endswith(".json") and "/cves/" in name):
                    continue
                basename = name.rsplit("/", 1)[-1]
                if not basename.upper().startswith("CVE-"):
                    continue
                try:
                    entry = _entry_from_json(json.loads(zf.read(name)))
                    if entry:
                        index[entry.cve_id] = entry
                        count += 1
                except Exception:
                    errors += 1

        logger.info("[CVEList] In-memory index built: %d CVEs, %d errors", count, errors)
        return index

    except Exception as exc:
        logger.error("[CVEList] Failed to download/parse zip: %s", exc)
        return {}


def build_cvelist_index(zip_path: str) -> Dict[str, CveEntry]:
    """
    Parse cvelistV5.zip and return a dict keyed by uppercase CVE-ID.
    Only reads cveMetadata from each JSON — fast, ~60–80 MB RAM for 400 K CVEs.
    """
    index: Dict[str, CveEntry] = {}
    zip_path = Path(zip_path)
    if not zip_path.exists():
        logger.warning("[CVEList] zip not found at %s — bulk enrichment skipped", zip_path)
        return index

    logger.info("[CVEList] Building index from %s …", zip_path)
    count = errors = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if not (name.endswith(".json") and "/cves/" in name):
                    continue
                basename = name.rsplit("/", 1)[-1]
                if not basename.upper().startswith("CVE-"):
                    continue
                try:
                    data = json.loads(zf.read(name))
                    entry = _entry_from_json(data)
                    if entry:
                        index[entry.cve_id] = entry
                        count += 1
                except Exception:
                    errors += 1
    except Exception as e:
        logger.error("[CVEList] Failed to open zip: %s", e)
        return index

    logger.info("[CVEList] Index built: %d CVEs loaded, %d errors", count, errors)
    return index


async def run_cvelist_enrichment_loop(
    db,
    index: Dict[str, CveEntry],
    *,
    startup_delay: float = 5.0,
    run_once: bool = False,
):
    """
    Bulk enrichment loop using the local zip index.
    Runs at startup to fill historical data, then exits when all rows are done.
    """
    if not index:
        logger.warning("[CVEList] Index empty — bulk enrichment skipped.")
        return

    logger.info("[CVEList] Bulk enrichment loop started (%d entries in index).", len(index))
    if startup_delay:
        await asyncio.sleep(startup_delay)

    while True:
        try:
            rows = await _fetch_pending(db, 500)
            if not rows:
                logger.info("[CVEList] Bulk enrichment complete — all rows processed.")
                return  # hand off to live sync loop

            done = not_found = 0
            for row in rows:
                entry = index.get(str(row["cve_id"] or "").strip().upper())
                if entry:
                    await _apply_entry(db, row["id"], entry)
                    done += 1
                else:
                    await _mark_not_found(db, row["id"])
                    not_found += 1

            await db._conn.commit()
            logger.info("[CVEList] Bulk enriched %d rows (%d not found).", done, not_found)

            if run_once:
                return

        except Exception as exc:
            logger.error("[CVEList] Bulk loop error: %s", exc)
            if run_once:
                raise
            await asyncio.sleep(30)


# ── ② Live GitHub polling (every 5 minutes) ───────────────────────────────────

class _GitHubPoller:
    """Polls CVEProject/cvelistV5 commits via GitHub API and fetches changed CVE JSONs."""

    def __init__(self, github_token: Optional[str] = None):
        self._token = github_token
        self._last_checked: Optional[str] = None  # ISO timestamp of last poll
        self._headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "ThreatIntel-TIP/1.0",
        }
        if github_token:
            self._headers["Authorization"] = f"Bearer {github_token}"

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    async def get_commits_since(self, client: httpx.AsyncClient, since: str) -> List[str]:
        """Return list of commit SHAs since the given ISO timestamp."""
        shas = []
        page = 1
        while True:
            try:
                r = await client.get(
                    f"{_GH_API_BASE}/commits",
                    params={"since": since, "per_page": 100, "page": page},
                    headers=self._headers,
                    timeout=_HTTP_TIMEOUT,
                )
                if r.status_code == 403:
                    logger.warning("[CVEList] GitHub API rate limited — will retry next poll.")
                    break
                if r.status_code != 200:
                    logger.warning("[CVEList] GitHub commits API returned %d", r.status_code)
                    break
                data = r.json()
                if not data:
                    break
                shas.extend(c["sha"] for c in data)
                if len(data) < 100:
                    break
                page += 1
            except Exception as e:
                logger.warning("[CVEList] GitHub commits fetch error: %s", e)
                break
        return shas

    async def get_changed_cve_files(self, client: httpx.AsyncClient, sha: str) -> List[str]:
        """Return list of CVE file paths changed in a given commit."""
        paths = []
        try:
            r = await client.get(
                f"{_GH_API_BASE}/commits/{sha}",
                headers=self._headers,
                timeout=_HTTP_TIMEOUT,
            )
            if r.status_code != 200:
                return paths
            for f in r.json().get("files", []):
                fname = f.get("filename", "")
                # Only care about CVE JSON files e.g. cves/2026/6xxx/CVE-2026-6411.json
                if fname.endswith(".json") and "/cves/" in fname:
                    basename = fname.rsplit("/", 1)[-1]
                    if basename.upper().startswith("CVE-"):
                        paths.append(fname)
        except Exception as e:
            logger.warning("[CVEList] Commit detail fetch error (sha=%s): %s", sha[:8], e)
        return paths

    async def fetch_cve_json(self, client: httpx.AsyncClient, file_path: str) -> Optional[CveEntry]:
        """Fetch a single CVE JSON from raw.githubusercontent.com and parse it."""
        url = f"{_GH_RAW_BASE}/{file_path}"
        try:
            r = await client.get(url, headers=self._headers, timeout=_HTTP_TIMEOUT)
            if r.status_code != 200:
                return None
            data = r.json()
            return _entry_from_json(data)
        except Exception as e:
            logger.debug("[CVEList] Raw fetch error (%s): %s", file_path, e)
            return None

    async def poll_once(self, db) -> Tuple[int, int]:
        """
        Run one poll cycle.
        Returns (updated_count, new_pending_enriched).
        """
        since = self._last_checked or self._now_iso()
        poll_start = self._now_iso()

        async with httpx.AsyncClient() as client:
            shas = await self.get_commits_since(client, since)
            if not shas:
                logger.debug("[CVEList] No new commits since %s", since)
                self._last_checked = poll_start
                return 0, 0

            logger.info("[CVEList] %d new commit(s) since %s", len(shas), since)

            # Collect unique changed CVE file paths across all commits
            changed_paths: dict[str, str] = {}  # cve_id -> file_path (last wins)
            for sha in shas:
                paths = await self.get_changed_cve_files(client, sha)
                for path in paths:
                    basename = path.rsplit("/", 1)[-1].replace(".json", "").upper()
                    if CVE_ID_RE.match(basename):
                        changed_paths[basename] = path
                await asyncio.sleep(0.2)   # be polite to GitHub API

            logger.info("[CVEList] %d unique CVE files changed", len(changed_paths))

            updated = 0
            for cve_id, file_path in changed_paths.items():
                # Only fetch if this CVE is in our ICS DB
                if not await _cve_exists_in_db(db, cve_id):
                    continue
                entry = await self.fetch_cve_json(client, file_path)
                if entry:
                    rows_updated = await _apply_by_cve_id(db, cve_id, entry)
                    if rows_updated:
                        updated += rows_updated
                        logger.debug("[CVEList] Updated %d row(s) for %s (pub: %s)",
                                     rows_updated, cve_id, entry.date_published)
                await asyncio.sleep(0.05)

            if updated:
                await db._conn.commit()
                logger.info("[CVEList] Live sync: updated %d ICS rows from GitHub.", updated)

        # Also catch any newly added ICS advisories that haven't been enriched yet
        pending = await _fetch_pending(db, 200)
        new_enriched = 0
        if pending:
            logger.info("[CVEList] Re-enriching %d newly added pending rows from index.", len(pending))
            # We don't have the index here — mark them for the next bulk pass
            # (the bulk loop already ran at startup; new rows come via ICS sync)
            # So fetch them individually from GitHub
            async with httpx.AsyncClient() as client:
                for row in pending:
                    cve_id = str(row["cve_id"] or "").strip().upper()
                    if not CVE_ID_RE.match(cve_id):
                        await _mark_not_found(db, row["id"])
                        continue
                    # Build path: CVE-YYYY-NNNNN → cves/YYYY/NNNxxx/CVE-YYYY-NNNNN.json
                    parts = cve_id.split("-")  # ['CVE', 'YYYY', 'NNNNN']
                    if len(parts) >= 3:
                        year_part = parts[1]
                        num_part  = parts[2]
                        # GitHub folder: last 3 digits zeroed, e.g. 6411 → 6xxx
                        folder = num_part[:-3] + "xxx" if len(num_part) > 3 else "0xxx"
                        file_path = f"cves/{year_part}/{folder}/{cve_id}.json"
                        entry = await self.fetch_cve_json(client, file_path)
                        if entry:
                            await _apply_entry(db, row["id"], entry)
                            new_enriched += 1
                        else:
                            await _mark_not_found(db, row["id"])
                    await asyncio.sleep(0.1)
                await db._conn.commit()

        self._last_checked = poll_start
        return updated, new_enriched


async def run_cvelist_live_sync_loop(
    db,
    github_token: Optional[str] = None,
    *,
    startup_delay: float = 30.0,
    poll_interval: float = _POLL_INTERVAL_SECS,
):
    """
    Async background loop: polls GitHub CVEProject/cvelistV5 every 5 minutes,
    downloads only changed CVE JSONs, and updates matching ICS advisory rows.

    github_token — optional GitHub personal access token for higher rate limits
                   (60 req/hr unauthenticated → 5000 req/hr authenticated).
    """
    poller = _GitHubPoller(github_token=github_token)
    logger.info(
        "[CVEList] Live sync loop started (poll every %ds, token=%s).",
        int(poll_interval),
        "yes" if github_token else "no (60 req/hr limit)",
    )

    # Small delay so the bulk enrichment loop can finish first
    await asyncio.sleep(startup_delay)

    while True:
        try:
            updated, new_enriched = await poller.poll_once(db)
            if updated or new_enriched:
                logger.info(
                    "[CVEList] Live sync done: %d rows updated, %d new rows enriched.",
                    updated, new_enriched,
                )
        except Exception as exc:
            logger.error("[CVEList] Live sync error: %s", exc)

        await asyncio.sleep(poll_interval)
