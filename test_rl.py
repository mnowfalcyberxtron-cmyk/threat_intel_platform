import asyncio
from connectors.ransomware_live import RansomwareLiveConnector

async def main():
    c = RansomwareLiveConnector()
    res = await c.scrape_group_iocs('alphv')
    for x in res: print(x)

asyncio.run(main())
