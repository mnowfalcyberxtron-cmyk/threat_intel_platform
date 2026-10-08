import asyncio
from database.db import Database
from utils.excel_exporter import ExcelExporter
import sys

async def main():
    db = Database()
    await db.initialize()
    exporter = ExcelExporter(db)
    
    res = await db.get_ics_advisories(page_size=20, year=2026, month=7)
    rows = res.get('items', [])
    for i, r in enumerate(rows):
        print(f"Row {i}: {r.get('ics_number')} | {r.get('cve_id')} | {r.get('vendor')} | {r.get('product')} | ai_enriched: {r.get('ai_enriched')}")
    
    # Let's check how many total rows we get when we just pull all
    res_all = await db.get_ics_advisories(page_size=50000)
    print(f"Total rows pulled for export: {len(res_all.get('items', []))}")
    
    await db.close()

asyncio.run(main())
