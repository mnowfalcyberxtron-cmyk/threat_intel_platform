import asyncio
import sys
import os

# Add the current directory to sys.path to import local modules
sys.path.append(os.getcwd())

from database.db import Database

async def run():
    db = Database()
    await db.initialize()
    
    # Get count before sync
    async with db._conn.execute("SELECT COUNT(*) FROM onion_sites") as cur:
        before = (await cur.fetchone())[0]
    
    # Sync discovered onion sites from victims
    new_count = await db.sync_discovered_onions()
    
    # Get count after sync
    async with db._conn.execute("SELECT COUNT(*) FROM onion_sites") as cur:
        after = (await cur.fetchone())[0]
        
    print(f"Sites in DB: {before} -> {after} (New: {new_count})")
    await db.close()

if __name__ == "__main__":
    asyncio.run(run())
