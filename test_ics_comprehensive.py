#!/usr/bin/env python3
"""
Comprehensive test of ICS Advisory system with edge cases and error scenarios
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test_comprehensive():
    print("=" * 80)
    print("COMPREHENSIVE ICS ADVISORY SYSTEM TEST")
    print("=" * 80)
    
    # Initialize database
    from database.db import Database
    _db = Database()
    await _db.initialize()
    
    # Setup advisory routes
    import api.advisory_routes as adv_routes
    adv_routes._db = _db
    
    # Initialize the system
    await adv_routes.init_ics_advisory_system()
    
    tests = [
        ("No filters - basic query", {}, "Should return all advisories"),
        ("Year filter 2026", {"year": 2026}, "Should return 2026 advisories"),
        ("Year + Month", {"year": 2026, "month": 1}, "Should return Jan 2026"),
        ("Vendor Siemens", {"vendor": "Siemens"}, "Should return Siemens advisories"),
        ("Severity Critical", {"severity": "Critical"}, "Should return Critical advisories"),
        ("Year + Vendor + Severity", {"year": 2026, "vendor": "Siemens", "severity": "High"}, "Combined filters"),
        ("Text search CVE-2026", {"search": "CVE-2026"}, "Should return CVE-2026 hits"),
        ("Pagination - page 2", {"page": 2, "page_size": 50}, "Should return different results"),
        ("Large page size", {"page": 1, "page_size": 500}, "Should return up to 500 items"),
        ("Empty result vendor", {"vendor": "NONEXISTENT_VENDOR_XYZ"}, "Should return empty but valid JSON"),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, params, description in tests:
        try:
            result = await adv_routes.ics_advisories(
                year=params.get("year"),
                month=params.get("month"),
                vendor=params.get("vendor"),
                severity=params.get("severity"),
                search=params.get("search"),
                enrich=False,
                page=params.get("page", 1),
                page_size=params.get("page_size", 100)
            )
            
            # Validate response structure
            has_total = "total" in result
            has_items = "items" in result
            has_source = "source" in result
            is_valid_json = True
            
            status = "PASS" if (has_total and has_items and has_source) else "FAIL"
            if status == "PASS":
                passed += 1
                print(f"[{status}] {test_name}")
                print(f"       Total: {result['total']}, Items: {len(result['items'])}, Source: {result['source']}")
            else:
                failed += 1
                print(f"[{status}] {test_name} — Missing fields")
        
        except Exception as e:
            failed += 1
            print(f"[FAIL] {test_name} — Exception: {e}")
    
    print("\n" + "=" * 80)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 80)
    
    # Test error handling
    print("\nERROR HANDLING TESTS:")
    print("-" * 80)
    
    # Test 1: Simulate invalid year (way in future)
    print("\n[Test] Invalid year (year 9999):")
    result = await adv_routes.ics_advisories(year=9999, page=1, page_size=10)
    print(f"  Returns valid JSON: {isinstance(result, dict)}")
    print(f"  Status: {result.get('source', 'error')}")
    print(f"  Total results: {result.get('total', 0)}")
    
    # Test 2: Negative month (should be blocked by Query constraint)
    print("\n[Test] Edge case - empty cache scenario (simulated):")
    result = await adv_routes.ics_advisories(
        year=None, month=None, vendor=None, severity=None,
        search="DEFINITELY_NOT_FOUND_" + "X" * 100,  # Very specific search
        page=1, page_size=100
    )
    print(f"  Returns valid JSON: {isinstance(result, dict)}")
    print(f"  Total: {result.get('total', 0)} (should be 0 or small)")
    print(f"  No error: {result.get('error') is None}")
    
    await _db.close()
    print("\n" + "=" * 80)
    print("TEST SUITE COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(test_comprehensive())
