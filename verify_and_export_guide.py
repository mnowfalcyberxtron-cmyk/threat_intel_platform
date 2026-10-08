#!/usr/bin/env python3
"""Check actual data status and show user how to verify/download."""
import asyncio
from database.db import Database

async def main():
    db = Database()
    await db.initialize()
    
    print("\n" + "=" * 90)
    print("🔍 THREAT INTEL PLATFORM - DATA STATUS & EXPORT GUIDE")
    print("=" * 90)
    print()
    
    # ===== ONION SITES STATUS =====
    print("🕷️  DARK WEB MONITORING - ONION SITES")
    print("-" * 90)
    
    total_onion = await db._query_val("SELECT COUNT(*) FROM onion_sites")
    online_onion = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status = '200'")
    offline_onion = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status IS NOT NULL AND last_status != '200' AND last_status != 'pending'")
    pending_onion = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status IS NULL OR last_status = 'pending'")
    
    print(f"Total sites configured:      {total_onion:,}")
    print(f"✅ Online (HTTP 200):        {online_onion:,} ({100*online_onion/(total_onion or 1):.1f}%)")
    print(f"❌ Offline/Error:            {offline_onion:,} ({100*offline_onion/(total_onion or 1):.1f}%)")
    print(f"⏳ Pending/Not scanned:      {pending_onion:,} ({100*pending_onion/(total_onion or 1):.1f}%)")
    print()
    
    # Show sample
    async with db._conn.execute(
        "SELECT url, last_status, last_checked FROM onion_sites WHERE last_status IS NOT NULL ORDER BY last_checked DESC LIMIT 5"
    ) as cur:
        samples = await cur.fetchall()
        if samples:
            print("Recent scans:")
            for s in samples:
                status = "🟢 ONLINE" if s['last_status'] == '200' else "🔴 OFFLINE"
                print(f"  {status} | {s['url']} | {s['last_checked']}")
    print()
    
    # ===== BREACH MARKETS STATUS =====
    print("🛒  BREACH MARKET MONITORING")
    print("-" * 90)
    
    total_markets = await db._query_val("SELECT COUNT(*) FROM breach_markets")
    online_markets = await db._query_val("SELECT COUNT(*) FROM breach_markets WHERE last_status = '200'")
    offline_markets = await db._query_val("SELECT COUNT(*) FROM breach_markets WHERE last_status IS NOT NULL AND last_status != '200' AND last_status != 'pending'")
    pending_markets = await db._query_val("SELECT COUNT(*) FROM breach_markets WHERE last_status IS NULL OR last_status = 'pending'")
    
    print(f"Total markets configured:    {total_markets:,}")
    print(f"✅ Online (HTTP 200):        {online_markets:,} ({100*online_markets/(total_markets or 1):.1f}%)")
    print(f"❌ Offline/Error:            {offline_markets:,} ({100*offline_markets/(total_markets or 1):.1f}%)")
    print(f"⏳ Pending/Not scanned:      {pending_markets:,} ({100*pending_markets/(total_markets or 1):.1f}%)")
    print()
    
    # Show samples
    async with db._conn.execute(
        "SELECT name, url, last_status, last_checked FROM breach_markets WHERE last_status IS NOT NULL ORDER BY last_checked DESC LIMIT 5"
    ) as cur:
        samples = await cur.fetchall()
        if samples:
            print("Recent scans:")
            for s in samples:
                status = "🟢 ONLINE" if s['last_status'] == '200' else "🔴 OFFLINE"
                print(f"  {status} | {s['name'][:40]:40} | {s['url'][:30]:30} | {s['last_checked']}")
    print()
    
    # ===== ICS ADVISORIES =====
    print("📋 ICS ADVISORY ENRICHMENT")
    print("-" * 90)
    
    total_ics = await db._query_val("SELECT COUNT(*) FROM ics_advisories")
    poc_yes = await db._query_val("SELECT COUNT(*) FROM ics_advisories WHERE poc_availability = 'Yes'")
    poc_no = await db._query_val("SELECT COUNT(*) FROM ics_advisories WHERE poc_availability = 'No'")
    poc_likely = await db._query_val("SELECT COUNT(*) FROM ics_advisories WHERE poc_availability = 'Likely'")
    patch_yes = await db._query_val("SELECT COUNT(*) FROM ics_advisories WHERE patch_availability = 'Yes'")
    
    print(f"Total ICS advisories:        {total_ics:,}")
    print(f"POC Availability:")
    print(f"  • Likely:                 {poc_likely:,}")
    print(f"  • Yes:                    {poc_yes:,}")
    print(f"  • No:                     {poc_no:,}")
    print(f"Patch Availability:")
    print(f"  • Yes:                    {patch_yes:,}")
    print()
    
    # ===== EXCEL EXPORT INFO =====
    print("💾 EXCEL EXPORT")
    print("-" * 90)
    print()
    print("📍 DOWNLOAD METHODS:")
    print()
    print("1️⃣  VIA API ENDPOINT (Direct Download):")
    print("    URL: http://localhost:8003/api/export/excel")
    print("    Method: GET")
    print("    Returns: threatintel_export.xlsx with:")
    print("      • ICS Advisories by month (with POC/Patch fields)")
    print("      • Breach Markets (with status)")
    print("      • Onion Sites (with status)")
    print("      • Uptime History (last 30 days)")
    print()
    print("2️⃣  PROGRAMMATIC (Python):")
    print("    import requests")
    print("    r = requests.get('http://localhost:8003/api/export/excel')")
    print("    with open('threatintel_export.xlsx', 'wb') as f:")
    print("        f.write(r.content)")
    print()
    print("3️⃣  SHELL/CURL:")
    print("    curl -o threatintel_export.xlsx http://localhost:8003/api/export/excel")
    print()
    
    # ===== UI GUIDE =====
    print("🖥️  UI FEATURES:")
    print("-" * 90)
    print()
    print("DARK WEB MANAGER (🌑 button in sidebar):")
    print("  • Shows 3 sections: Active Sites | Pending/Configured | Offline Sites")
    print("  • Status badges: ● ACTIVE | ◌ PENDING | ✗ OFFLINE")
    print("  • Each site shows last checked timestamp")
    print("  • Add/Edit/Delete user-configured sites")
    print("  • 🧪 Test button to manually verify a site")
    print()
    print("BREACH MARKETS (🛒 button in sidebar):")
    print("  • Lists 3,341 markets with status tracking")
    print("  • Status bars show: Online | Offline | Pending counts")
    print("  • View screenshots of markets")
    print("  • Search and filter by status")
    print()
    print("EXPORT OPTIONS:")
    print("  • Use the API endpoint above to download Excel")
    print("  • No download button in UI yet (but export works via API)")
    print()
    
    # ===== VERIFICATION =====
    print("✅ VERIFICATION CHECKLIST:")
    print("-" * 90)
    print()
    print("To confirm systems are working:")
    print()
    print("1. Dark Web Status:")
    if online_onion > 0:
        print(f"   ✅ {online_onion} onion sites are verified online")
    else:
        print(f"   ⚠️  No sites verified online yet - might need more time or Tor connectivity")
    print()
    print("2. Breach Markets Status:")
    if online_markets > 0:
        print(f"   ✅ {online_markets} breach markets confirmed online")
    else:
        print(f"   ⚠️  Markets showing offline - checking connectivity/Tor")
    print()
    print("3. ICS Enrichment:")
    poc_total = poc_yes + poc_no + poc_likely
    if poc_total > 0:
        print(f"   ✅ {poc_total:,} advisories have POC availability data")
        if patch_yes > 0:
            print(f"   ✅ {patch_yes:,} advisories have patch availability data")
    else:
        print(f"   ❌ No POC data yet")
    print()
    
    print("=" * 90)
    print("✨ HOW TO VERIFY:")
    print("=" * 90)
    print()
    print("1. CLICK Dark Web Manager → Check for ● ACTIVE sites")
    print("   If you see online sites: Dark web monitoring is WORKING ✓")
    print()
    print("2. CLICK Breach Markets → Check status bar for Online count")
    print("   If Online > 0: Market monitoring is WORKING ✓")
    print()
    print("3. DOWNLOAD Excel to see all data:")
    print("   curl -o threat_intel.xlsx 'http://localhost:8003/api/export/excel'")
    print()
    print("4. CLICK Refresh (↻) button to force manual data collection")
    print()
    
    await db.close()

if __name__ == "__main__":
    asyncio.run(main())
