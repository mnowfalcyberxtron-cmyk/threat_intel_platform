import asyncio, sys
sys.path.insert(0, '.')
from database.db import Database

async def test():
    db = Database()
    await db.initialize()
    
    # 1. Check column state
    total = (await db._conn.execute("SELECT COUNT(*) FROM ics_advisories")).fetchone
    total = (await (await db._conn.execute("SELECT COUNT(*) FROM ics_advisories")).fetchone())[0]
    done = (await (await db._conn.execute("SELECT COUNT(*) FROM ics_advisories WHERE cvelist_status='done'")).fetchone())[0]
    pending = (await (await db._conn.execute("SELECT COUNT(*) FROM ics_advisories WHERE cvelist_status='pending' OR cvelist_status IS NULL")).fetchone())[0]
    not_found = (await (await db._conn.execute("SELECT COUNT(*) FROM ics_advisories WHERE cvelist_status='not_found'")).fetchone())[0]
    
    print(f"Total rows:  {total}")
    print(f"Done:        {done}")
    print(f"Pending:     {pending}")
    print(f"Not found:   {not_found}")
    
    # 2. Show a sample done row
    row = await (await db._conn.execute(
        "SELECT cve_id, cve_published_date, cve_pub_year, cve_pub_month FROM ics_advisories WHERE cvelist_status='done' LIMIT 1"
    )).fetchone()
    if row:
        print("\nSample done row:", dict(row))
    
    # 3. Show cve_pub_years from meta
    meta = await db.get_ics_meta()
    print("\ncve_pub_years:", meta.get('cve_pub_years'))
    
    await db.close()

asyncio.run(test())
