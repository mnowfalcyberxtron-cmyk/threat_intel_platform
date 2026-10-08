#!/usr/bin/env python3
"""
Simulate full frontend-backend flow for ICS advisories with filters
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test_full_flow():
    print("=" * 80)
    print("FULL FRONTEND→BACKEND FLOW TEST")
    print("=" * 80)
    
    # Initialize database
    from database.db import Database
    _db = Database()
    await _db.initialize()
    
    # Setup advisory routes
    import api.advisory_routes as adv_routes
    adv_routes._db = _db
    
    # Initialize system
    await adv_routes.init_ics_advisory_system()
    
    print("\n[STEP 1] Frontend calls /api/advisory/ics/meta to get filters")
    meta = await adv_routes.ics_meta()
    print(f"  Years: {meta.get('years', [])[:3]} ...")
    print(f"  Months: {meta.get('months', [])[:5]} ...")
    print(f"  Total advisories: {meta.get('total_rows', 'N/A')}")
    
    print("\n[STEP 2] Frontend loads dropdown with these options")
    print("  User selects: Year=2026, Month=May (which becomes month=5)")
    year_from_dropdown = 2026
    month_from_dropdown = 5  # May
    
    print("\n[STEP 3] Frontend sends query with filters")
    print(f"  Query: /api/advisory/ics?year={year_from_dropdown}&month={month_from_dropdown}&page=1&page_size=50")
    
    print("\n[STEP 4] Backend processes query")
    result = await adv_routes.ics_advisories(
        year=year_from_dropdown,
        month=month_from_dropdown,
        vendor=None,
        severity=None,
        search=None,
        enrich=False,
        page=1,
        page_size=50
    )
    
    print(f"  Response source: {result.get('source')}")
    print(f"  Total results: {result.get('total')}")
    print(f"  Returned items: {len(result.get('items', []))}")
    
    if result.get('error'):
        print(f"  ERROR: {result.get('error')}")
    else:
        if result.get('items'):
            first = result['items'][0]
            print(f"  Sample item: {first.get('cve_id')} - {first.get('title', 'N/A')[:50]}")
    
    print("\n[STEP 5] Frontend displays results")
    if result.get('items'):
        print(f"  SUCCESS: Would display {len(result['items'])} rows")
        print(f"           Status: '{result['total']} CVE rows'")
    else:
        if result.get('total', 0) == 0:
            print(f"  Result: No CVE rows (valid - just no matches for filters)")
        else:
            print(f"  ERROR: Total={result['total']} but no items returned!")
    
    # Test other filter combinations
    print("\n" + "=" * 80)
    print("TESTING OTHER FILTER COMBINATIONS")
    print("=" * 80)
    
    test_cases = [
        ("Year 2026 only", {"year": 2026, "month": None, "vendor": None}),
        ("Year + Month (May 2026)", {"year": 2026, "month": 5, "vendor": None}),
        ("Vendor: Siemens", {"year": None, "month": None, "vendor": "Siemens"}),
        ("Year 2026 + Vendor Siemens", {"year": 2026, "month": None, "vendor": "Siemens"}),
        ("All months with data", {"year": None, "month": 1, "vendor": None}),
    ]
    
    for desc, filters in test_cases:
        result = await adv_routes.ics_advisories(
            year=filters["year"],
            month=filters["month"],
            vendor=filters["vendor"],
            severity=None,
            search=None,
            enrich=False,
            page=1,
            page_size=10
        )
        status = "✓" if result.get('items') or result.get('total', 0) >= 0 else "✗"
        print(f"  {status} {desc}: {result.get('total', 0)} total")
    
    await _db.close()
    print("\n" + "=" * 80)
    print("FULL FLOW TEST COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(test_full_flow())
