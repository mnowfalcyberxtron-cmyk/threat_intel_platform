#!/usr/bin/env python3
"""Test ICS meta endpoint to verify months are returned"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test_meta():
    print("Testing ICS Meta Endpoint")
    print("=" * 80)
    
    # Initialize database
    from database.db import Database
    _db = Database()
    await _db.initialize()
    
    # Test get_ics_meta directly
    print("\n[Direct DB Query]")
    meta = await _db.get_ics_meta()
    print(f"Total advisories: {meta.get('total')}")
    print(f"Years available: {meta.get('years', [])[:5]}")
    print(f"Months available: {meta.get('months', [])}")
    print(f"Vendors (first 3): {meta.get('vendors', [])[:3]}")
    print(f"Severities: {meta.get('by_severity', [])}")
    
    # Now test via API endpoint
    print("\n[Via API Endpoint]")
    import api.advisory_routes as adv_routes
    adv_routes._db = _db
    
    # Get the endpoint function
    result = await adv_routes.ics_meta()
    print(f"Total: {result.get('total')}")
    print(f"Years: {result.get('years', [])[:5]}")
    print(f"Months: {result.get('months', [])}")
    print(f"Vendors count: {len(result.get('vendors', []))}")
    
    await _db.close()
    print("\n" + "=" * 80)

if __name__ == "__main__":
    asyncio.run(test_meta())
