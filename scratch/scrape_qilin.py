import asyncio
from database.db import Database
from connectors.ransomware_live import RansomwareLiveConnector

async def main():
    db = Database()
    await db.initialize()
    c = RansomwareLiveConnector()
    iocs = await c.scrape_group_iocs("qilin")
    print(f"Scraped {len(iocs)} IOCs for qilin")
    for ioc in iocs:
        await db.upsert_ioc(ioc)
    print("Done")

if __name__ == "__main__":
    asyncio.run(main())
