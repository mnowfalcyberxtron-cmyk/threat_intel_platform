
import asyncio
import aiosqlite
from pathlib import Path

async def check():
    db_path = "data/threat_intel.db"
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT COUNT(*) FROM onion_sites") as c:
            print(f"Onions: {(await c.fetchone())[0]}")
        async with db.execute("SELECT COUNT(*) FROM breach_markets") as c:
            print(f"Breach Markets: {(await c.fetchone())[0]}")

asyncio.run(check())
