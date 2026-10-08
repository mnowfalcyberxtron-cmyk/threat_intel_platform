import asyncio
import sys
sys.path.append('.')
from database.db import Database
from connectors.onion_monitor import OnionMonitorConnector

import logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
async def test_scan():
    db = Database()
    await db.initialize()
    
    cur = await db._conn.execute("SELECT id, group_name, url FROM onion_sites WHERE group_name LIKE '%ransomhub%' OR group_name LIKE '%play%' LIMIT 1")
    row = await cur.fetchone()
    
    if not row:
        print('Onion site not found.')
    else:
        site_id = row['id']
        print(f'Triggering targeted scan for {row["group_name"]} ({row["url"]}) [ID: {site_id}]')
        
        connector = OnionMonitorConnector(db)
        await connector.run_targeted_scan(site_id)
        
        cur = await db._conn.execute("SELECT last_status, screenshot_path FROM onion_sites WHERE id=?", (site_id,))
        res = await cur.fetchone()
        print('Scan result:', dict(res))
    
    await db.close()

asyncio.run(test_scan())
