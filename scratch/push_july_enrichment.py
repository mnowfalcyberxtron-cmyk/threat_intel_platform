"""
Batch AI enrichment push starting strictly with July 2026 advisories, then proceeding to August & September 2026.
Uses OpenRouter (with Groq fallback) to update title, impact, affected_version, fixed_version, vendor, product, patch/poc flags, and XTRON score.
"""

import asyncio
import sqlite3
import json
import re
import sys
from datetime import datetime, timezone
import httpx

from config import settings
from connectors.ics_ai_enrichment import (
    _fetch_cve_json,
    _extract_from_cve_json,
    _infer_patch_bool_from_cve,
    _infer_poc_bool_from_cve,
    _calc_xtron_score,
    _call_ai_for_enrichment,
)

async def run_july_enrichment_push():
    sys.stdout.reconfigure(encoding='utf-8')
    groq_key = getattr(settings, "GROQ_API_KEY", "") or ""
    groq_model = "llama3-70b-8192"
    openrouter_key = getattr(settings, "OPENROUTER_API_KEY", "") or ""
    openrouter_model = "google/gemma-4-31b-it"
    github_token = getattr(settings, "GITHUB_TOKEN", "") or ""

    conn = sqlite3.connect('data/threat_intel.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Query July 2026 unenriched advisories first
    cur.execute("""
        SELECT id, ics_number, cve_id, title, vendor, product, severity,
               cvss_score, sector, cwe, impact, affected_version, fixed_version,
               patch_availability, poc_availability, kev_flag,
               cve_published_date, cve_updated_date
        FROM ics_advisories
        WHERE (ai_enriched IS NULL OR ai_enriched = 0)
          AND cve_published_date >= '2026-07-01'
          AND cve_published_date <= '2026-07-31'
          AND cve_id IS NOT NULL
        ORDER BY cve_published_date ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    print(f"Pushing AI enrichment for {len(rows)} July 2026 advisories...")

    _pfx = re.compile(r'^(?:affected|fixed)\s*:\s*', re.IGNORECASE)

    async with httpx.AsyncClient() as client:
        for i, row in enumerate(rows, 1):
            cve_id = str(row["cve_id"]).strip().upper()
            row_id = row["id"]
            print(f"[{i}/{len(rows)}] Enriching July 2026: {cve_id} (Pub: {str(row.get('cve_published_date'))[:10]})...")

            cve_info = {}
            raw_cve = await _fetch_cve_json(client, cve_id, github_token)
            if raw_cve:
                cve_info = _extract_from_cve_json(raw_cve)

            patch_bool = _infer_patch_bool_from_cve(cve_info, row.get("patch_availability", ""))
            poc_bool = _infer_poc_bool_from_cve(cve_info, row.get("kev_flag", ""))
            score = _calc_xtron_score(row.get("severity", ""), poc_bool)

            ai_res = await _call_ai_for_enrichment(
                client, row, cve_info,
                groq_key, groq_model,
                openrouter_key, openrouter_model,
            )

            if ai_res:
                aff_text = _pfx.sub("", ai_res.get("affected_text", "")).strip()
                fix_text = _pfx.sub("", ai_res.get("fixed_text", "")).strip()
                ai_vendor = (ai_res.get("vendor") or "").strip()
                ai_product = (ai_res.get("product") or "").strip()

                conn.execute("""
                    UPDATE ics_advisories SET
                        vendor = CASE WHEN ? != '' THEN ? ELSE vendor END,
                        product = CASE WHEN ? != '' THEN ? ELSE product END,
                        title = CASE WHEN ? != '' THEN ? ELSE title END,
                        impact = CASE WHEN ? != '' THEN ? ELSE impact END,
                        affected_version = CASE WHEN ? != '' THEN ? ELSE affected_version END,
                        fixed_version = CASE WHEN ? != '' THEN ? ELSE fixed_version END,
                        patch_available_bool = ?,
                        poc_available_bool = ?,
                        xtron_score = ?,
                        ai_enriched = 1,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    ai_vendor, ai_vendor,
                    ai_product, ai_product,
                    ai_res.get("title", ""), ai_res.get("title", ""),
                    ai_res.get("impact", ""), ai_res.get("impact", ""),
                    aff_text, aff_text,
                    fix_text, fix_text,
                    "True" if patch_bool else "False",
                    "True" if poc_bool else "False",
                    score,
                    datetime.now(timezone.utc).isoformat(),
                    row_id,
                ))
                print(f"   -> AI Enriched: Vendor={ai_vendor or row.get('vendor')}, Product={ai_product or row.get('product')}, XTRON={score}")
            else:
                conn.execute("""
                    UPDATE ics_advisories SET
                        patch_available_bool = ?,
                        poc_available_bool = ?,
                        xtron_score = ?,
                        ai_enriched = 1,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    "True" if patch_bool else "False",
                    "True" if poc_bool else "False",
                    score,
                    datetime.now(timezone.utc).isoformat(),
                    row_id,
                ))
                print(f"   -> Fallback saved: XTRON={score}")

            conn.commit()
            await asyncio.sleep(0.5)

    print("July 2026 AI enrichment push completed!")

if __name__ == '__main__':
    asyncio.run(run_july_enrichment_push())
