import asyncio, aiosqlite

async def check():
    async with aiosqlite.connect('data/threat_intel.db') as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, group_name, screenshot_path FROM onion_sites "
            "WHERE screenshot_path IS NOT NULL AND screenshot_path != '' LIMIT 5"
        ) as cur:
            rows = await cur.fetchall()
            for r in rows:
                print(dict(r))
        
        async with db.execute(
            "SELECT COUNT(*) as total, "
            "SUM(CASE WHEN screenshot_path IS NOT NULL AND screenshot_path != '' THEN 1 ELSE 0 END) as with_ss "
            "FROM onion_sites"
        ) as cur:
            row = await cur.fetchone()
            print(f'Total sites: {row[0]}, With screenshots: {row[1]}')

asyncio.run(check())
