#!/usr/bin/env python3
"""Test the full get_ics_advisories function with year and month filters"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test():
    from database.db import Database
    db = Database()
    await db.initialize()
    
    print("Testing get_ics_advisories with filters:")
    print("=" * 80)
    
    # Test 1: Year only
    result = await db.get_ics_advisories(year=2026, page_size=10)
    print(f"\n[Test 1] Year 2026 only:")
    print(f"  Total: {result['total']}")
    print(f"  Sample: {result['items'][0]['cve_id'] if result['items'] else 'None'}")
    
    # Test 2: Month only
    result = await db.get_ics_advisories(month=5, page_size=10)
    print(f"\n[Test 2] Month 05 (May) only:")
    print(f"  Total: {result['total']}")
    if result['items']:
        print(f"  Sample: {result['items'][0]['cve_id']} - {result['items'][0].get('release_date', 'N/A')}")
    
    # Test 3: Year + Month combined
    result = await db.get_ics_advisories(year=2026, month=5, page_size=50)
    print(f"\n[Test 3] Year 2026 + Month 05 (May):")
    print(f"  Total: {result['total']}")
    if result['items']:
        for i, item in enumerate(result['items'][:5]):
            print(f"    {i+1}. {item['cve_id']}: {item.get('release_date', 'N/A')}")
    else:
        print(f"  No items - checking if this is expected...")
        # Check if there are ANY CVE-2026 with May dates
        raw = await db._query_val('''
            SELECT COUNT(*) FROM ics_advisories 
            WHERE cve_id LIKE 'CVE-2026-%'
            AND (substr(release_date, 6, 2) = '05' 
                 OR substr(release_date, 1, 2) = '05' 
                 OR substr(release_date, 1, 1) = '5' 
                 OR release_date LIKE '%-05-%')
        ''')
        print(f"  Raw count from manual query: {raw}")
    
    await db.close()

asyncio.run(test())
