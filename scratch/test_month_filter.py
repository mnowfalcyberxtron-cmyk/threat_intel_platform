import asyncio
import logging
import sys

# Configure mock logger
logging.basicConfig(level=logging.INFO)
sys.path.append('.')

from api.advisory_routes import _get_ics_data, _row_filter_month, _parse_date

async def test_filter():
    print("Fetching ICS data...")
    rows = await _get_ics_data()
    print(f"Total rows: {len(rows)}")
    
    # Check type and value of month in first 10 rows
    print("\nFirst 10 rows month values:")
    for i, r in enumerate(rows[:10]):
        m_val = r.get("month")
        f_m = _row_filter_month(r)
        print(f"Row {i+1}: cve={r.get('cve_id')}, month_field={m_val} (type: {type(m_val)}), filter_month={f_m} (type: {type(f_m)})")
        
    # Test filtering by a month that should have items (e.g., month = 5)
    for test_m in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]:
        filtered = [r for r in rows if _row_filter_month(r) == test_m]
        print(f"Month {test_m}: found {len(filtered)} items")

if __name__ == "__main__":
    asyncio.run(test_filter())
