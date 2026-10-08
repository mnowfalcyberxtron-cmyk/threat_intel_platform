#!/usr/bin/env python3
"""
Diagnostic script to test ICS advisory system from scratch
"""
import asyncio
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

async def main():
    print("=" * 60)
    print("ICS Advisory System Diagnostic")
    print("=" * 60)
    
    # Step 1: Check if database.db exists
    db_path = Path("database.db")
    print(f"\n[1] Database file exists: {db_path.exists()}")
    if db_path.exists():
        print(f"    File size: {db_path.stat().st_size} bytes")
    
    # Step 2: Initialize database
    print(f"\n[2] Initializing database...")
    from database.db import Database
    _db = Database()
    try:
        await _db.initialize()
        print("    ✓ Database initialized")
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return
    
    # Step 3: Check if ics_advisories table exists
    print(f"\n[3] Checking ics_advisories table...")
    try:
        meta = await _db.get_ics_meta()
        print(f"    ✓ ICS table exists")
        print(f"      Total advisories: {meta.get('total', 0)}")
        print(f"      Years: {meta.get('years', [])[:5]}")
        print(f"      Vendors (first 5): {meta.get('vendors', [])[:5]}")
    except Exception as e:
        print(f"    ✗ Error checking meta: {e}")
    
    # Step 4: Import advisory routes and set _db
    print(f"\n[4] Importing advisory routes...")
    try:
        import api.advisory_routes as adv_routes
        adv_routes._db = _db
        print("    ✓ Imported and set _db")
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return
    
    # Step 5: Initialize ICS system
    print(f"\n[5] Initializing ICS advisory system...")
    try:
        await adv_routes.init_ics_advisory_system()
        print("    ✓ ICS system initialized")
    except Exception as e:
        print(f"    ✗ Error: {e}")
    
    # Step 6: Check again after init
    print(f"\n[6] Checking ics_advisories table after init...")
    try:
        meta = await _db.get_ics_meta()
        print(f"    Total advisories: {meta.get('total', 0)}")
    except Exception as e:
        print(f"    ✗ Error: {e}")
    
    # Step 7: Test get_ics_advisories directly
    print(f"\n[7] Testing database query...")
    try:
        result = await _db.get_ics_advisories(page=1, page_size=10)
        print(f"    ✓ Query successful")
        print(f"      Total: {result.get('total')}, Items: {len(result.get('items', []))}")
        if result.get('error'):
            print(f"      Error: {result.get('error')}")
    except Exception as e:
        print(f"    ✗ Error: {e}")
    
    # Step 8: Test with filters
    print(f"\n[8] Testing with year filter (2026)...")
    try:
        result = await _db.get_ics_advisories(page=1, page_size=10, year=2026)
        print(f"    Total: {result.get('total')}, Items: {len(result.get('items', []))}")
        if result.get('error'):
            print(f"    Error: {result.get('error')}")
    except Exception as e:
        print(f"    Error: {e}")
    
    await _db.close()
    print("\n" + "=" * 60)
    print("Diagnostic complete")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
