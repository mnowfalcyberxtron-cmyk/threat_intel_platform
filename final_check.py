#!/usr/bin/env python3
"""Check ICS enrichment and generate Excel."""
import asyncio
from database.db import Database
from utils.excel_exporter import ExcelExporter
import time

async def main():
    db = Database()
    await db.initialize()
    
    print("Checking ICS enrichment status...")
    total = await db._query_val('SELECT COUNT(*) FROM ics_advisories')
    poc = await db._query_val("SELECT COUNT(*) FROM ics_advisories WHERE COALESCE(poc_availability, '') NOT IN ('Unknown', '')")
    patch = await db._query_val("SELECT COUNT(*) FROM ics_advisories WHERE COALESCE(patch_availability, '') NOT IN ('Unknown', '')")
    
    print(f'Total ICS: {total}')
    print(f'POC enriched: {poc} ({100*poc/total if total else 0:.1f}%)')
    print(f'Patch enriched: {patch} ({100*patch/total if total else 0:.1f}%)')
    print()
    
    # Show samples
    print("Sample records:")
    async with db._conn.execute('SELECT ics_number, poc_availability, patch_availability FROM ics_advisories LIMIT 3') as cur:
        for row in await cur.fetchall():
            print(f"  {row['ics_number']}: POC={row['poc_availability']}, Patch={row['patch_availability']}")
    print()
    
    # Generate Excel
    print("Generating Excel export...")
    try:
        exporter = ExcelExporter(db)
        start = time.time()
        path = await exporter.export()
        elapsed = time.time() - start
        print(f"✅ Excel generated in {elapsed:.1f}s at {path}")
        
        import os
        if os.path.exists(path):
            size_mb = os.path.getsize(path) / (1024 * 1024)
            print(f"✅ File size: {size_mb:.2f} MB")
    except Exception as e:
        print(f"❌ Excel export failed: {e}")
        import traceback
        traceback.print_exc()
    
    await db.close()

if __name__ == "__main__":
    asyncio.run(main())
