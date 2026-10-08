#!/usr/bin/env python3
"""Test month filter query directly"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test():
    from database.db import Database
    db = Database()
    await db.initialize()
    
    # Test the month filter logic directly
    print("Testing month filter logic for May (05):")
    print("=" * 80)
    
    # Check each condition separately
    results = await db._query_list('''
        SELECT cve_id, release_date, 
               substr(release_date, 6, 2) as pos6_7,
               substr(release_date, 1, 2) as pos1_2
        FROM ics_advisories 
        WHERE substr(release_date, 6, 2) = '05' OR substr(release_date, 1, 2) = '05' OR release_date LIKE '%-05-%'
        LIMIT 10
    ''')
    
    print(f"Found {len(results)} items matching May filter:")
    for r in results:
        print(f"  {r['cve_id']}: {r['release_date']} (pos6_7={r['pos6_7']}, pos1_2={r['pos1_2']})")
    
    # Now test with year AND month combined
    print("\n" + "=" * 80)
    print("Testing Year 2026 + Month 05 combined:")
    print("=" * 80)
    
    results2 = await db._query_list('''
        SELECT cve_id, release_date, 
               substr(cve_id, 5, 4) as cve_year
        FROM ics_advisories 
        WHERE (cve_id LIKE 'CVE-2026-%' OR substr(release_date, 1, 4) = '2026')
              AND (substr(release_date, 6, 2) = '05' OR substr(release_date, 1, 2) = '05' OR release_date LIKE '%-05-%')
        LIMIT 10
    ''')
    
    print(f"Found {len(results2)} items matching Year 2026 + Month 05:")
    for r in results2:
        print(f"  {r['cve_id']}: {r['release_date']} (cve_year={r['cve_year']})")
    
    # Get a count
    count = await db._query_val('''
        SELECT COUNT(*) 
        FROM ics_advisories 
        WHERE (cve_id LIKE 'CVE-2026-%' OR substr(release_date, 1, 4) = '2026')
              AND (substr(release_date, 6, 2) = '05' OR substr(release_date, 1, 2) = '05' OR release_date LIKE '%-05-%')
    ''')
    print(f"\nTotal count: {count}")
    
    await db.close()

asyncio.run(test())
