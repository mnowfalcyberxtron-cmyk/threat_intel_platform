
import asyncio
import aiosqlite
from pathlib import Path

async def check():
    db_path = "data/threat_intel.db"
    if not Path(db_path).exists():
        print("DB not found")
        return
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT COUNT(*) FROM iocs") as c:
            print(f"IOCs: {(await c.fetchone())[0]}")
        async with db.execute("SELECT COUNT(*) FROM ransomware_victims") as c:
            print(f"Victims: {(await c.fetchone())[0]}")
        async with db.execute("SELECT COUNT(*) FROM alerts") as c:
            print(f"Alerts: {(await c.fetchone())[0]}")

asyncio.run(check())
