#!/usr/bin/env python3
"""Force ICS Advisory re-sync with enriched POC/Patch fields."""
import asyncio
from database.db import Database
from api.advisory_routes import _get_ics_data, _derive_poc_availability, _derive_patch_available

async def fix_ics():
    db = Database()
    await db.initialize()
    
    print("=" * 80)
    print("FORCE-SYNCING ICS ADVISORIES WITH ENRICHED DATA")
    print("=" * 80)
    print()
    
    try:
        # Step 1: Clear old records
        print("Step 1: Clearing existing ICS advisory records...")
        await db._conn.execute("DELETE FROM ics_advisories")
        await db._conn.commit()
        print("✅ Cleared ICS table")
        print()
        
        # Step 2: Fetch fresh data
        print("Step 2: Fetching ICS advisory data from APIs...")
        rows = await _get_ics_data()
        print(f"✅ Fetched {len(rows)} advisory records from APIs")
        print()
        
        # Step 3: Enrich and insert
        print("Step 3: Enriching and inserting records into database...")
        count = 0
        for i, row in enumerate(rows):
            try:
                # Build record with enrichment
                record = {
                    "ics_number": row.get("ics_number") or row.get("advisory_id") or "",
                    "cve_id": row.get("cve_id") or "N/A",
                    "title": row.get("title") or "",
                    "affected_vendor": row.get("affected_vendor") or "",
                    "affected_application": row.get("affected_application") or "",
                    "cvss_score": row.get("cvss_score") or "",
                    "cvss_severity": row.get("cvss_severity") or "medium",
                    "release_date": row.get("release_date") or row.get("published_date") or "",
                    "last_updated": row.get("last_updated") or "",
                    "advisory_url": row.get("advisory_url") or row.get("url") or "",
                    "sector": row.get("sector") or "",
                    # Apply enrichment functions
                    "patch_availability": _derive_patch_available(
                        row.get("affected_application") or "",
                        row.get("cvss_score") or ""
                    ),
                    "poc_availability": _derive_poc_availability(row),
                    "impact": row.get("impact") or "",
                    "affected_version": row.get("affected_version") or "",
                    "fixed_version": row.get("fixed_version") or "",
                    "cwe": row.get("cwe") or "",
                    "vendor_hq": row.get("vendor_hq") or "",
                    "product_distribution": row.get("product_distribution") or "",
                    "kev_flag": row.get("kev_flag") or "",
                    "nist_url": row.get("nist_url") or "",
                    "csaf_url": row.get("csaf_url") or "",
                    "data_source": row.get("data_source") or "csv",
                }
                
                _, is_new = await db.upsert_ics_advisory(record)
                if is_new:
                    count += 1
                    
                if (i + 1) % 1000 == 0:
                    print(f"   Progress: {i+1}/{len(rows)} records processed")
                    
            except Exception as e:
                print(f"   ⚠️  Failed to process record {i}: {e}")
                continue
        
        print(f"✅ Inserted {count} new ICS advisory records")
        print()
        
        # Step 4: Verify enrichment
        print("Step 4: Verifying enrichment...")
        total = await db._query_val("SELECT COUNT(*) FROM ics_advisories")
        poc_enriched = await db._query_val(
            "SELECT COUNT(*) FROM ics_advisories WHERE poc_availability != 'Unknown' AND poc_availability IS NOT NULL AND poc_availability != ''"
        ) or 0
        patch_enriched = await db._query_val(
            "SELECT COUNT(*) FROM ics_advisories WHERE patch_availability != 'Unknown' AND patch_availability IS NOT NULL AND patch_availability != ''"
        ) or 0
        
        print(f"✅ Total ICS advisories:       {total:,}")
        print(f"✅ POC Availability enriched: {poc_enriched:,} ({100*poc_enriched/(total or 1):.1f}%)")
        print(f"✅ Patch Availability enriched: {patch_enriched:,} ({100*patch_enriched/(total or 1):.1f}%)")
        print()
        
        # Show sample of enriched data
        print("Step 5: Sample enriched records:")
        async with db._conn.execute(
            "SELECT ics_number, cve_id, title, patch_availability, poc_availability FROM ics_advisories LIMIT 5"
        ) as cur:
            samples = await cur.fetchall()
            for sample in samples:
                print(f"   • {sample['ics_number']} / {sample['cve_id']}")
                print(f"     Patch: {sample['patch_availability']} | POC: {sample['poc_availability']}")
        
        print()
        print("=" * 80)
        print("✅ ICS ADVISORY ENRICHMENT COMPLETE")
        print("=" * 80)
        
    except Exception as e:
        print(f"Error during ICS sync: {e}")
        import traceback
        traceback.print_exc()
    
    await db.close()

if __name__ == "__main__":
    asyncio.run(fix_ics())
