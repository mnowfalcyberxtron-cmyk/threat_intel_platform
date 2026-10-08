#!/usr/bin/env python3
import asyncio
from database.db import Database

async def check():
    db = Database()
    await db.initialize()
    
    total = await db._query_val('SELECT COUNT(*) FROM onion_sites')
    online = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status = '200'")
    offline = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status IS NOT NULL AND last_status != '200' AND last_status != 'pending'")
    
    hist = await db._query_val("SELECT COUNT(*) FROM status_history WHERE target_type = 'onion_site'")
    screenshots = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE screenshot_path IS NOT NULL")
    
    print(f'Total sites: {total}')
    print(f'Online (HTTP 200): {online}')
    print(f'Offline/Error: {offline}')
    print(f'Status history entries: {hist}')
    print(f'Screenshots captured: {screenshots}')
    print()
    
    async with db._conn.execute('SELECT url, last_status FROM onion_sites WHERE last_status = "200" LIMIT 5') as cur:
        results = await cur.fetchall()
        if results:
            print('Sample ONLINE sites:')
            for r in results:
                print(f'  🟢 {r["url"][:50]:50} | {r["last_status"]}')
    
    await db.close()

asyncio.run(check())
