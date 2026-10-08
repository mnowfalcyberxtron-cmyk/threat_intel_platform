"""
Repair local ICS advisory rows so official CVEList fields and AI fields persist.

Run from the project root:
    python repair_ics_official_and_ai_persistence.py

This is intentionally local-database only. It does not deploy or push anything.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from connectors.cvelist_enrichment import build_cvelist_index, _merge_official_blob


DB_PATH = Path("data/threat_intel.db")
CVELIST_ZIP = Path("cvelistV5.zip")

VENDOR_HQ = {
    "fortinet": "United States",
    "milestone systems": "Denmark",
    "red hat": "United States",
    "furuno electric co., ltd.": "Japan",
    "furuno electric co.,ltd.": "Japan",
    "atn-b1": "Global",
}


def _json_obj(value):
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def main() -> None:
    if not DB_PATH.exists():
        raise SystemExit(f"Database not found: {DB_PATH}")
    if not CVELIST_ZIP.exists():
        raise SystemExit(f"CVEList archive not found: {CVELIST_ZIP}")

    index = build_cvelist_index(str(CVELIST_ZIP))
    if not index:
        raise SystemExit("CVEList index is empty; no repair applied.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT *
        FROM ics_advisories
        WHERE cve_id IS NOT NULL
          AND TRIM(UPPER(cve_id)) NOT IN ('N/A', 'NONE', '')
        """
    ).fetchall()

    official_updates = 0
    json_updates = 0
    fake_ai_resets = 0

    for row in rows:
        row_id = row["id"]
        cve_id = str(row["cve_id"] or "").strip().upper()
        entry = index.get(cve_id)

        raw = _json_obj(row["raw_data"])
        normalized = _json_obj(row["normalized_data"])
        ai_enriched = int(row["ai_enriched"] or 0)

        if entry:
            official_raw = _json_obj(_merge_official_blob(raw, entry))
            official_normalized = _json_obj(_merge_official_blob(normalized, entry))

            vendor = entry.vendor or row["vendor"] or ""
            product = entry.product or row["product"] or ""
            hq = VENDOR_HQ.get(vendor.lower(), "") or row["vendor_hq"] or ""

            affected_version = row["affected_version"] if ai_enriched else (entry.affected_version or row["affected_version"] or "")
            fixed_version = row["fixed_version"] if ai_enriched else (entry.fixed_version or row["fixed_version"] or "")
            severity = (entry.cvss_severity.lower() if entry.cvss_severity else row["severity"]) or "medium"

            for blob in (official_raw, official_normalized):
                blob["affected_vendor"] = vendor
                blob["affected_application"] = product
                blob["vendor"] = vendor
                blob["product"] = product
                if entry.title:
                    blob["title"] = entry.title
                if entry.impact:
                    blob["impact"] = entry.impact
                if hq:
                    blob["vendor_hq"] = hq
                if ai_enriched:
                    for key in ("title", "impact", "affected_version", "fixed_version"):
                        if row[key]:
                            blob[key] = row[key]

            cur.execute(
                """
                UPDATE ics_advisories
                   SET cve_published_date = ?,
                       cve_updated_date = ?,
                       cve_pub_year = ?,
                       cve_pub_month = ?,
                       title = CASE WHEN COALESCE(ai_enriched, 0) = 1 THEN title ELSE COALESCE(NULLIF(?, ''), title) END,
                       impact = CASE WHEN COALESCE(ai_enriched, 0) = 1 THEN impact ELSE COALESCE(NULLIF(?, ''), impact) END,
                       cvss_score = COALESCE(NULLIF(?, ''), cvss_score),
                       severity = COALESCE(NULLIF(?, ''), severity),
                       cwe = COALESCE(NULLIF(?, ''), cwe),
                       affected_version = COALESCE(NULLIF(?, ''), affected_version),
                       fixed_version = COALESCE(NULLIF(?, ''), fixed_version),
                       raw_data = ?,
                       normalized_data = ?,
                       cvelist_status = 'done'
                 WHERE id = ?
                """,
                (
                    entry.date_published,
                    entry.date_updated,
                    entry.pub_year,
                    entry.pub_month,
                    entry.title,
                    entry.impact,
                    entry.cvss_score,
                    severity,
                    entry.cwe,
                    affected_version,
                    fixed_version,
                    json.dumps(official_raw),
                    json.dumps(official_normalized),
                    row_id,
                ),
            )
            official_updates += 1

        # Keep deterministic AI helper fields in the JSON blobs too.
        raw = _json_obj(cur.execute("SELECT raw_data FROM ics_advisories WHERE id=?", (row_id,)).fetchone()[0])
        normalized = _json_obj(cur.execute("SELECT normalized_data FROM ics_advisories WHERE id=?", (row_id,)).fetchone()[0])
        helper_updates = {
            "ai_enriched": row["ai_enriched"],
            "patch_available_bool": row["patch_available_bool"],
            "poc_available_bool": row["poc_available_bool"],
            "xtron_score": row["xtron_score"],
        }
        changed = False
        for blob in (raw, normalized):
            for key, value in helper_updates.items():
                if value not in (None, "") and blob.get(key) != value:
                    blob[key] = value
                    changed = True
        if changed:
            cur.execute(
                "UPDATE ics_advisories SET raw_data=?, normalized_data=? WHERE id=?",
                (json.dumps(raw), json.dumps(normalized), row_id),
            )
            json_updates += 1

        # Do not let rows with only score/booleans masquerade as complete AI text.
        impact = str(row["impact"] or "")
        if ai_enriched and not impact.startswith("A successful exploit"):
            cur.execute(
                "UPDATE ics_advisories SET ai_enriched=0 WHERE id=?",
                (row_id,),
            )
            fake_ai_resets += 1

    conn.commit()
    conn.close()

    print(f"official_cvelist_rows_repaired={official_updates}")
    print(f"json_ai_helper_rows_repaired={json_updates}")
    print(f"fake_ai_enriched_rows_reset={fake_ai_resets}")


if __name__ == "__main__":
    main()
