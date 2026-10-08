import os
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

import asyncio
from api.advisory_routes import _get_ics_data, _row_filter_month, _row_cve_year

async def main():
    rows = await _get_ics_data()
    print(f"Total rows fetched: {len(rows)}")
    
    unique_months = set()
    unique_years = set()
    none_months = 0
    none_years = 0
    
    for r in rows:
        m = _row_filter_month(r)
        y = _row_cve_year(r)
        if m:
            unique_months.add(m)
        else:
            none_months += 1
            
        if y:
            unique_years.add(y)
        else:
            none_years += 1
            
    print(f"Unique months: {sorted(list(unique_months))}")
    print(f"None months count: {none_months}")
    print(f"Unique years (first 10): {sorted(list(unique_years))[:10]}")
    print(f"None years count: {none_years}")

asyncio.run(main())
