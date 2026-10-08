import asyncio
import sqlite3
import json
import logging
import httpx
from connectors.ics_ai_enrichment import _fetch_cve_json, _extract_from_cve_json

logging.basicConfig(level=logging.INFO)

async def align_all_from_github_cvelist():
    conn = sqlite3.connect('data/threat_intel.db')
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, cve_id, vendor, product, title, affected_version, fixed_version, raw_data 
        FROM ics_advisories 
        WHERE cve_published_date >= '2026-07-01' 
          AND cve_id IS NOT NULL 
          AND TRIM(UPPER(cve_id)) NOT IN ('N/A', 'NONE', '')
    """)
    rows = cursor.fetchall()
    print(f"Auditing & aligning {len(rows)} CVE rows from official GitHub cvelistV5...")

    updated_count = 0

    async with httpx.AsyncClient() as client:
        for row_id, cve_id, db_vendor, db_product, db_title, db_aff, db_fix, raw_json in rows:
            cve_data = await _fetch_cve_json(client, cve_id)
            if not cve_data:
                continue
                
            extracted = _extract_from_cve_json(cve_data)
            affected_prods = extracted.get("affected_products") or []
            if not affected_prods:
                continue

            primary = affected_prods[0]
            gh_vendor = primary.get("vendor", "").strip()
            gh_product = primary.get("product", "").strip()

            if not gh_vendor or gh_vendor.lower() in ("n/a", "unknown", "none"):
                continue

            # Check if GitHub vendor differs meaningfully from DB vendor
            # e.g. 'Milestone Systems A/S' vs 'Siemens'
            if gh_vendor.lower() != db_vendor.lower() and not (db_vendor.lower() in gh_vendor.lower() or gh_vendor.lower() in db_vendor.lower()):
                print(f"[{cve_id}] Realigning Vendor: '{db_vendor}' -> '{gh_vendor}' | Product: '{db_product}' -> '{gh_product}'")
                
                # Format affected version / fixed version from GitHub JSON if available
                ver_list = primary.get("versions") or []
                aff_ver_str = db_aff
                fix_ver_str = db_fix
                
                for v in ver_list:
                    if v.get("lessThan"):
                        aff_ver_str = f"{gh_product} prior to v{v['lessThan']}"
                        fix_ver_str = f"Update {gh_product} to v{v['lessThan']} or later"
                        break
                    elif v.get("version") and v.get("version") != "0":
                        aff_ver_str = f"{gh_product} v{v['version']}"

                # Update raw_data as well
                try:
                    raw = json.loads(raw_json) if raw_json else {}
                except Exception:
                    raw = {}
                    
                raw['affected_vendor'] = gh_vendor
                raw['affected_application'] = gh_product

                cursor.execute("""
                    UPDATE ics_advisories
                    SET vendor = ?, product = ?, raw_data = ?
                    WHERE id = ?
                """, (gh_vendor, gh_product, json.dumps(raw), row_id))
                updated_count += 1

    conn.commit()
    conn.close()
    print(f"Finished! Successfully realigned {updated_count} CVEs using GitHub cvelistV5 as single source of truth.")

if __name__ == '__main__':
    asyncio.run(align_all_from_github_cvelist())
