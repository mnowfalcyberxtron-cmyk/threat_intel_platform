"""
utils/excel_exporter.py — Automated Excel export engine for ThreatIntel TIP v2.5

Export strategy (matches user requirement):
  • ICS Advisories  → MONTHLY sheets (2024_January, 2025_March, …)
                      Red fill on CRITICAL/HIGH severity or CVSS >= 9.0
  • Breach Markets  → FIXED sheet 'Breach_Markets'  (full current snapshot)
  • Onion Sites     → FIXED sheet 'Onion_Sites'      (full current snapshot)
  • Status History  → FIXED sheet 'Uptime_History'   (last N days of checks)
                      Red fill on offline/timeout rows

Excel is written to reports/threat_intel_export.xlsx (configurable via
settings.EXCEL_EXPORT_PATH).  The file is created fresh each run; openpyxl
merges nothing — it simply overwrites every sheet.

Usage (async):
    from utils.excel_exporter import ExcelExporter
    exporter = ExcelExporter(db)
    path = await exporter.export()
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("utils.excel_exporter")

# ── colour constants (openpyxl hex, no '#') ──────────────────────────────────
_RED_FILL_HEX   = "FFE1E1"   # light red background
_RED_FONT_HEX   = "CC0000"   # dark red text
_HEADER_FILL    = "1F3864"   # dark navy header
_HEADER_FONT    = "FFFFFF"   # white text
_ALT_ROW_FILL   = "F2F5FB"   # very light blue alternate rows


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _month_sheet_name(date_str: str) -> str:
    """
    Convert ISO date string or advisory release_date to a sheet name like '2025_May'.
    Falls back to 'Unknown' if unparseable.
    """
    if not date_str:
        return "Unknown"
    s = str(date_str).strip()
    try:
        if "/" in s:
            parts = s.split("/")
            if len(parts) >= 3:
                m = int(parts[0])
                y = int(parts[2].split()[0])
                import calendar
                if 1 <= m <= 12:
                    return f"{y}_{calendar.month_name[m]}"
        else:
            s = s[:10]
            dt = datetime.strptime(s, "%Y-%m-%d")
            return dt.strftime("%Y_%B")
    except Exception:
        pass
    
    # Try YYYY-MM
    try:
        dt = datetime.strptime(s[:7], "%Y-%m")
        return dt.strftime("%Y_%B")
    except Exception:
        pass
        
    return "Unknown"


def _safe_str(v: Any) -> str:
    """Convert any value to a clean string safe for Excel."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Y" if v else "N"
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return str(v).strip()


def _normalize_export_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the canonical DB row and normalized_data content into one export-safe dict."""
    flat = dict(row)
    try:
        nd = json.loads(flat.get("normalized_data") or "{}")
        if isinstance(nd, dict):
            for key, value in nd.items():
                if key not in flat or flat.get(key) in (None, "", "Unknown"):
                    flat[key] = value
    except Exception:
        pass

    for key in ["severity", "cvss_score", "patch_availability", "poc_availability", "kev_flag"]:
        value = flat.get(key)
        if value is None:
            flat[key] = ""
        elif isinstance(value, bool):
            flat[key] = "Y" if value else "N"

    return flat


def _is_truthy_text(value: Any) -> bool:
    return str(value or "").strip().lower() in {"true", "yes", "y", "1", "kev"}


def _is_falsey_text(value: Any) -> bool:
    return str(value or "").strip().lower() in {"false", "no", "n", "0"}


def _clean_ai_prefix(value: Any) -> str:
    text = str(value or "").strip()
    return re.sub(r"^(?:affected|fixed)\s*:\s*", "", text, flags=re.IGNORECASE).strip()


def _normalize_ics_dashboard_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Mirror dashboard display fields so Excel exports do not drift."""
    flat = _normalize_export_row(row)

    score_val = None
    try:
        match = re.search(r"(\d+(?:\.\d+)?)", str(flat.get("cvss_score") or ""))
        if match:
            score_val = float(match.group(1))
    except (ValueError, TypeError):
        score_val = None

    if score_val is not None:
        if score_val >= 9.0:
            flat["severity"] = "Critical"
        elif score_val >= 7.0:
            flat["severity"] = "High"
        elif score_val >= 4.0:
            flat["severity"] = "Medium"
        elif score_val > 0:
            flat["severity"] = "Low"

    if flat.get("affected_vendor") and not flat.get("vendor"):
        flat["vendor"] = flat.get("affected_vendor")
    if flat.get("affected_application") and not flat.get("product"):
        flat["product"] = flat.get("affected_application")

    flat["affected_version"] = _clean_ai_prefix(flat.get("affected_version"))
    flat["fixed_version"] = _clean_ai_prefix(flat.get("fixed_version"))

    patch_bool = str(flat.get("patch_available_bool") or "").strip().lower()
    if patch_bool == "true" or _is_truthy_text(flat.get("patch_yn")):
        patch_yn = "Y"
    elif patch_bool == "false" or _is_falsey_text(flat.get("patch_yn")):
        patch_yn = "N"
    elif _is_truthy_text(flat.get("patch_availability")):
        patch_yn = "Y"
    elif _is_falsey_text(flat.get("patch_availability")):
        patch_yn = "N"
    else:
        patch_yn = ""
    flat["PATCH (Y/N)"] = patch_yn
    if patch_yn:
        flat["patch_availability"] = "Yes" if patch_yn == "Y" else "No"

    poc_bool = str(flat.get("poc_available_bool") or "").strip().lower()
    if poc_bool == "true" or _is_truthy_text(flat.get("poc_yn")):
        poc_yn = "Y"
    elif poc_bool == "false" or _is_falsey_text(flat.get("poc_yn")):
        poc_yn = "N"
    elif _is_truthy_text(flat.get("poc_availability")) or _is_truthy_text(flat.get("kev_flag")):
        poc_yn = "Y"
    elif _is_falsey_text(flat.get("poc_availability")):
        poc_yn = "N"
    else:
        poc_yn = ""
    flat["POC (Y/N)"] = poc_yn
    if poc_yn:
        flat["poc_availability"] = "Yes" if poc_yn == "Y" else "No"

    try:
        xtron_score = int(flat.get("xtron_score"))
    except (TypeError, ValueError):
        sev_key = str(flat.get("severity") or "").strip().lower()
        sev_pts = 65 if sev_key == "critical" else (60 if sev_key == "high" else (50 if sev_key == "medium" else (35 if sev_key == "low" else 0)))
        poc_pts = 10 if poc_yn == "Y" else 0
        xtron_score = sev_pts + poc_pts if sev_pts else ""
    flat["XTRON SCORE"] = xtron_score

    return flat


class ExcelExporter:
    """
    Async Excel exporter.  Call `await exporter.export()` to generate the file.
    """

    def __init__(self, db, export_path: str = ""):
        self.db = db
        self._path = export_path or _get_default_path()

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    async def export(self, year: int = None, month: int = None, severity: str = None, vendor: str = None, search: str = None, filter_mode: str = "cve_published") -> str:
        """Generate the Excel workbook and return its absolute path."""
        try:
            from openpyxl import Workbook
            from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
        except ImportError:
            logger.error("openpyxl not installed. Run: pip install openpyxl")
            return ""

        Path(self._path).parent.mkdir(parents=True, exist_ok=True)

        wb = Workbook()
        wb.remove(wb.active)   # remove default blank sheet

        filtered_export = any([year, month, severity, vendor, search])
        await self._write_ics_sheets(wb, year=year, month=month, severity=severity, vendor=vendor, search=search, filter_mode=filter_mode)

        if not filtered_export:
            # Only include the full workbook extras when exporting the unfiltered dataset.
            await self._write_breach_markets_sheet(wb)
            await self._write_onion_sites_sheet(wb)
            await self._write_uptime_history_sheet(wb)

        if not wb.sheetnames:
            ws = wb.create_sheet(title="Summary")
            _write_sheet(
                ws,
                ["generated_at", "message"],
                [{"generated_at": _now_utc(), "message": "No exportable records found"}],
                lambda _row: False,
            )

        output = Path(self._path)
        tmp_path = output.with_suffix(".tmp.xlsx")
        try:
            wb.save(tmp_path)
            os.replace(tmp_path, output)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
        logger.info("✅ Excel exported to: %s", self._path)
        return self._path

    # ─────────────────────────────────────────────────────────────────────────
    # ICS — monthly sheets
    # ─────────────────────────────────────────────────────────────────────────

    async def _write_ics_sheets(self, wb, year: int = None, month: int = None, severity: str = None, vendor: str = None, search: str = None, filter_mode: str = "cve_published") -> None:
        """Fetch ICS advisories and bucket them by the active dashboard date mode."""
        result = await self.db.get_ics_advisories(page_size=50000, year=year, month=month, severity=severity, vendor=vendor, search=search, filter_mode=filter_mode)
        rows: List[Dict] = [_normalize_ics_dashboard_row(r) for r in result.get("items", [])]

        if not rows:
            logger.info("[Excel] No ICS advisories in DB — skipping monthly sheets")
            return

        # Group rows by month sheet name
        buckets: Dict[str, List[Dict]] = {}
        for r in rows:
            date_key = r.get("cve_published_date") if filter_mode == "cve_published" else None
            sheet = _month_sheet_name(
                date_key or r.get("release_date") or r.get("last_updated") or ""
            )
            buckets.setdefault(sheet, []).append(r)

        # Determine columns: start with fixed DB columns in a sensible order
        fixed_cols = [
            "ics_number", "cve_id", "title", "vendor", "product",
            "cvss_score", "severity", "release_date", "last_updated",
            "cve_published_date",
            "sector", "patch_availability", "poc_availability",
            "PATCH (Y/N)", "POC (Y/N)", "XTRON SCORE",
            "impact", "affected_version", "fixed_version", "cwe",
            "advisory_url", "vendor_hq", "product_distribution",
            "kev_flag", "data_source",
        ]

        # Keys from normalized_data that duplicate fixed_cols or are internal metadata
        _skip_normalized_keys = {
            "raw_data", "normalized_data",
            # Aliases of fixed_cols — already covered by vendor/product/severity
            "affected_vendor", "affected_application", "cvss_severity",
            "advisory_id", "ics_number", "cve_id", "title",
            "cvss_score", "release_date", "last_updated", "advisory_url",
            "sector", "patch_availability", "poc_availability", "impact",
            "affected_version", "fixed_version", "cwe", "data_source",
            "vendor_hq", "product_distribution", "kev_flag",
            "published_date", "cve_published_date",
            # Internal date-part metadata — not useful in Excel
            "release_year", "release_month", "update_year", "update_month",
            "cve_year", "published_year", "published_month", "year", "month",
            # AI enrichment internals — represented as helper columns
            "ai_enriched", "patch_available_bool", "poc_available_bool", "xtron_score",
        }

        # Collect any genuinely extra columns from normalized_data blobs
        extra_cols: List[str] = []
        for r in rows[:200]:                # sample first 200 rows for speed
            try:
                nd = json.loads(r.get("normalized_data") or "{}")
                for k in nd:
                    if k not in fixed_cols and k not in extra_cols and k not in _skip_normalized_keys:
                        extra_cols.append(k)
            except Exception:
                pass
        all_cols = fixed_cols + extra_cols

        for sheet_name in sorted(buckets.keys()):
            safe_name = sheet_name[:31]          # Excel sheet name max 31 chars
            ws = wb.create_sheet(title=safe_name)
            sheet_rows = buckets[sheet_name]

            # Merge normalized_data fields into each row and compute helper columns
            expanded: List[Dict] = []
            for r in sheet_rows:
                expanded.append(r)

            _write_sheet(ws, all_cols, expanded, _is_ics_critical)
            logger.debug("[Excel] Sheet '%s': %d rows", safe_name, len(expanded))

    # ─────────────────────────────────────────────────────────────────────────
    # Breach Markets — fixed sheet
    # ─────────────────────────────────────────────────────────────────────────

    async def _write_breach_markets_sheet(self, wb) -> None:
        """Write current state of all breach markets."""
        rows = await self.db._query_list(
            "SELECT * FROM breach_markets ORDER BY last_status, name"
        )
        if not rows:
            return
        cols = [
            "id", "name", "url", "site_type", "source",
            "active", "last_status", "last_checked",
            "screenshot_path", "description", "created_at", "updated_at",
        ]
        ws = wb.create_sheet(title="Breach_Markets")
        _write_sheet(ws, cols, rows, _is_offline)

    # ─────────────────────────────────────────────────────────────────────────
    # Onion Sites — fixed sheet
    # ─────────────────────────────────────────────────────────────────────────

    async def _write_onion_sites_sheet(self, wb) -> None:
        """Write current state of all monitored onion sites."""
        rows = await self.db.get_all_onion_sites(active_only=False)
        if not rows:
            return
        cols = [
            "id", "group_name", "url", "site_type",
            "active", "last_status", "last_checked",
            "page_title", "meta_generator", "screenshot_path", "created_at",
        ]
        ws = wb.create_sheet(title="Onion_Sites")
        _write_sheet(ws, cols, rows, _is_offline)

    # ─────────────────────────────────────────────────────────────────────────
    # Uptime History — fixed sheet (last 30 days)
    # ─────────────────────────────────────────────────────────────────────────

    async def _write_uptime_history_sheet(self, wb) -> None:
        """Write the raw status_history log for pattern analysis."""
        try:
            from config import settings
            limit = int(getattr(settings, "EXCEL_UPTIME_HISTORY_LIMIT", 20000) or 20000)
        except Exception:
            limit = 20000
        rows = await self.db.get_status_history(hours=720, limit=limit)  # 30 days, capped for responsive exports
        if not rows:
            logger.info("[Excel] No status_history data yet — skipping Uptime_History sheet")
            return
        cols = [
            "id", "target_type", "target_id", "name", "url",
            "status", "latency_ms", "timestamp",
        ]
        ws = wb.create_sheet(title="Uptime_History")
        _write_sheet(ws, cols, rows, _is_offline)
        logger.info("[Excel] Uptime_History: %d rows", len(rows))


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_ics_critical(row: Dict) -> bool:
    """Return True if the ICS row should be highlighted red."""
    sev = str(row.get("severity") or "").lower()
    if sev in ("critical", "high"):
        return True
    try:
        score = float(row.get("cvss_score") or 0)
        if score >= 9.0:
            return True
    except (ValueError, TypeError):
        pass
    return False


def _is_offline(row: Dict) -> bool:
    """Return True if the market/onion/history row should be highlighted red."""
    status = str(row.get("last_status") or row.get("status") or "").lower()
    active  = row.get("active", 1)
    if active == 0 or active == "0":
        return True
    bad_statuses = {"offline", "timeout", "offline/timeout", "failed", "0", "error"}
    if status in bad_statuses:
        return True
    if status.startswith("error:"):
        return True
    # Numeric HTTP status >= 400
    try:
        if int(status) >= 400:
            return True
    except (ValueError, TypeError):
        pass
    return False


def _write_sheet(
    ws,
    columns: List[str],
    rows: List[Dict],
    highlight_fn,
) -> None:
    """Write a formatted sheet: header row + data rows with targeted highlighting."""
    from openpyxl.styles import PatternFill, Font, Alignment

    header_fill = PatternFill(start_color=_HEADER_FILL, end_color=_HEADER_FILL, fill_type="solid")
    header_font = Font(bold=True, color=_HEADER_FONT, size=11)
    red_fill    = PatternFill(start_color=_RED_FILL_HEX, end_color=_RED_FILL_HEX, fill_type="solid")
    red_font    = Font(color=_RED_FONT_HEX, bold=True)
    alt_fill    = PatternFill(start_color=_ALT_ROW_FILL, end_color=_ALT_ROW_FILL, fill_type="solid")
    center      = Alignment(horizontal="center", vertical="center")
    wrap        = Alignment(wrap_text=True, vertical="top")

    # ── Header ────────────────────────────────────────────────────────────────
    for col_idx, col_name in enumerate(columns, start=1):
        cell = ws.cell(row=1, column=col_idx, value=col_name.upper().replace("_", " "))
        cell.fill  = header_fill
        cell.font  = header_font
        cell.alignment = center

    # ── Data rows ────────────────────────────────────────────────────────────
    for row_idx, row in enumerate(rows, start=2):
        is_red = highlight_fn(row)
        is_alt = (row_idx % 2 == 0)

        for col_idx, col_name in enumerate(columns, start=1):
            raw_val = row.get(col_name, "")
            # Keep integers as integers (e.g. XTRON SCORE) for proper Excel sorting
            if isinstance(raw_val, int):
                val = raw_val
            else:
                val = _safe_str(raw_val)
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.alignment = wrap
            if isinstance(val, str) and val.startswith("="):
                # Live formula: do not format as raw text
                pass
            if _should_highlight_cell(row, columns, col_name, is_red):
                cell.fill = red_fill
                cell.font = red_font
            elif is_alt:
                cell.fill = alt_fill

    # ── Column widths ─────────────────────────────────────────────────────────
    for col_idx, col_name in enumerate(columns, start=1):
        col_letter = ws.cell(row=1, column=col_idx).column_letter
        # Sample first 50 rows to estimate width
        max_len = len(col_name) + 2
        for row_idx in range(2, min(len(rows) + 2, 52)):
            cell_val = str(ws.cell(row=row_idx, column=col_idx).value or "")
            max_len = max(max_len, min(len(cell_val), 60))
        ws.column_dimensions[col_letter].width = max_len + 2

    # Freeze header row
    ws.freeze_panes = "A2"


def _should_highlight_cell(row: Dict, columns: List[str], col_name: str, is_red: bool) -> bool:
    """Keep warning colors focused instead of painting entire exported rows."""
    if not is_red:
        return False

    normalized = str(col_name or "").strip().lower()
    has_ics_columns = "cve_id" in columns or "ics_number" in columns
    if has_ics_columns:
        return normalized in {
            "severity",
            "cvss_score",
            "xtron score",
            "kev_flag",
        }

    # Onion/Breach/Uptime sheets: highlight only the status-related cells.
    return normalized in {
        "active",
        "last_status",
        "status",
        "latency_ms",
    }


def _get_default_path() -> str:
    try:
        from config import settings
        path = getattr(settings, "EXCEL_EXPORT_PATH", "")
        if path:
            p = Path(path)
            if not p.suffix:
                return str(p / "threat_intel_export.xlsx")
            return str(p)
    except Exception:
        pass
    return "reports/threat_intel_export.xlsx"
