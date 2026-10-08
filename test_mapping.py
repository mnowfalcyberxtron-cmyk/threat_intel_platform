import asyncio
import json
from database.db import Database
from api.advisory_routes import _map_db_row_to_frontend

async def main():
    db = Database()
    await db.initialize()
    r = await db.get_ics_advisories(page_size=5)
    for x in r['items']:
        d = _map_db_row_to_frontend(dict(x))
        print(f"CVE: {d.get('cve_id')}, Vendor: {d.get('affected_vendor')}, Product: {d.get('affected_application')}, Severity: {d.get('cvss_severity')}, CVSS: {d.get('cvss_score')}")

if __name__ == '__main__':
    asyncio.run(main())
