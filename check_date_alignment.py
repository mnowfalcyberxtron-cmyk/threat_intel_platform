#!/usr/bin/env python3
"""Check what release dates exist for CVE-2026"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def check():
    from database.db import Database
    db = Database()
    await db.initialize()
    
    # Check what release dates are stored for CVE-2026
    result = await db._query_list('''
        SELECT DISTINCT release_date, COUNT(*) as cnt 
        FROM ics_advisories 
        WHERE cve_id LIKE 'CVE-2026-%' 
        GROUP BY release_date 
        ORDER BY release_date DESC
        LIMIT 10
    ''')
    
    print('Release dates for CVE-2026:')
    for r in result:
        print(f'  {r.get("release_date")}: {r.get("cnt")} items')
    
    # Check if May data exists for ANY year
    may_result = await db._query_val('SELECT COUNT(*) FROM ics_advisories WHERE substr(release_date, 6, 2) = "05"')
    print(f'\nTotal items with May (05) as release month: {may_result}')
    
    # Check the actual min/max dates
    min_max = await db._query_list('SELECT MIN(release_date) as min_date, MAX(release_date) as max_date FROM ics_advisories WHERE release_date != ""')
    if min_max:
        print(f'\nDate range in database:')
        print(f'  Min: {min_max[0].get("min_date")}')
        print(f'  Max: {min_max[0].get("max_date")}')
    
    # Sample: Get CVE-2026 entries and their release dates
    samples = await db._query_list('SELECT cve_id, release_date FROM ics_advisories WHERE cve_id LIKE "CVE-2026-%" LIMIT 5')
    print(f'\nSample CVE-2026 entries:')
    for s in samples:
        print(f'  {s.get("cve_id")}: {s.get("release_date")}')
    
    await db.close()

asyncio.run(check())
