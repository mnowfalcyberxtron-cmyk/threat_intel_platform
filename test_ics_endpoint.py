#!/usr/bin/env python3
"""
Test the ICS advisory endpoint directly
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test_endpoint():
    print("=" * 70)
    print("Testing ICS Advisory Endpoint")
    print("=" * 70)
    
    # Initialize database
    from database.db import Database
    _db = Database()
    await _db.initialize()
    
    # Setup advisory routes
    import api.advisory_routes as adv_routes
    adv_routes._db = _db
    
    # Initialize the system
    await adv_routes.init_ics_advisory_system()
    
    # Now test the endpoint function directly
    print("\n[TEST 1] No filters:")
    try:
        result = await adv_routes.ics_advisories(
            year=None, month=None, vendor=None, severity=None, 
            search=None, enrich=False, page=1, page_size=10
        )
        print(f"  Total: {result.get('total')}")
        print(f"  Items: {len(result.get('items', []))}")
        print(f"  Source: {result.get('source')}")
        if result.get('error'):
            print(f"  Error: {result.get('error')}")
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[TEST 2] Year filter (2026):")
    try:
        result = await adv_routes.ics_advisories(
            year=2026, month=None, vendor=None, severity=None, 
            search=None, enrich=False, page=1, page_size=10
        )
        print(f"  Total: {result.get('total')}")
        print(f"  Items: {len(result.get('items', []))}")
        print(f"  Source: {result.get('source')}")
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[TEST 3] Vendor + Severity filters:")
    try:
        result = await adv_routes.ics_advisories(
            year=None, month=None, vendor="Siemens", severity="Critical", 
            search=None, enrich=False, page=1, page_size=10
        )
        print(f"  Total: {result.get('total')}")
        print(f"  Items: {len(result.get('items', []))}")
    except Exception as e:
        print(f"  ✗ Exception: {e}")
    
    print("\n[TEST 4] Search filter:")
    try:
        result = await adv_routes.ics_advisories(
            year=None, month=None, vendor=None, severity=None, 
            search="CVE-2026", enrich=False, page=1, page_size=10
        )
        print(f"  Total: {result.get('total')}")
        print(f"  Items: {len(result.get('items', []))}")
        if result.get('items'):
            print(f"  First item: {result['items'][0].get('cve_id', 'N/A')}")
    except Exception as e:
        print(f"  ✗ Exception: {e}")
    
    await _db.close()
    print("\n" + "=" * 70)

if __name__ == "__main__":
    asyncio.run(test_endpoint())
