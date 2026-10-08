#!/usr/bin/env python3
import asyncio
from database.db import Database

async def test():
    db = Database()
    await db.initialize()
    
    # Test 1: Check ICS count
    ics_count = await db._query_val('SELECT COUNT(*) FROM ics_advisories')
    print(f'✓ ICS Advisories in DB: {ics_count:,}')
    
    # Test 2: Check if data is there
    async with db._conn.execute('SELECT COUNT(*) FROM iocs') as cur:
        r = await cur.fetchone()
        iocs = r[0]
    print(f'✓ IOCs in DB: {iocs:,}')
    
    # Test 3: Check ransomware_victims
    async with db._conn.execute('SELECT COUNT(*) FROM ransomware_victims') as cur:
        r = await cur.fetchone()
        victims = r[0]
    print(f'✓ Ransomware Victims: {victims:,}')
    
    await db.close()

asyncio.run(test())
