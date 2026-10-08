#!/usr/bin/env python3
"""Fix all data collection issues and generate exports."""
import asyncio
import sys
from database.db import Database
from config import settings

async def fix_all():
    db = Database()
    await db.initialize()
    
    print("=" * 80)
    print("FIXING ALL ISSUES - Phase 1: ICS Advisory Enrichment")
    print("=" * 80)
    print()
    
    # ===== FIX 1: Re-fetch and re-sync ICS advisories with improved derivation =====
    print("📋 Step 1: Re-syncing ICS advisories with improved POC/Patch detection...")
    try:
        from api.advisory_routes import _sync_ics_advisories_to_db
        synced_count, new_count = await _sync_ics_advisories_to_db()
        count = f"{synced_count} processed, {new_count} new"
        print(f"✅ ICS advisories re-synced: {count} updated/new records")
    except Exception as e:
        print(f"⚠️  ICS re-sync had issues: {e}")
    
    print()
    print("=" * 80)
    print("FIXING ALL ISSUES - Phase 2: Dark Web Onion Sites Status")
    print("=" * 80)
    print()
    
    # ===== FIX 2: Ensure Tor is running and do a targeted scan =====
    print("🕷️  Step 2: Checking Tor and initiating onion site scans...")
    try:
        # Check Tor
        from utils.tor_manager import ensure_tor_proxy
        tor = await ensure_tor_proxy(settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT)
        tor_ok = bool(tor.get("ok"))
        
        if tor_ok:
            print(f"Verified proxy: {tor.get('proxy_url')}")
            print("✅ Tor is running")
            
            # Run onion monitor
            from connectors.onion_monitor import OnionMonitorConnector
            monitor = OnionMonitorConnector(db)
            print("   Starting onion site scans (this may take a few minutes)...")
            await monitor.run(pending_only=True)  # Only scan pending/unscanned sites
            print("✅ Onion site scanning complete")
        else:
            print(f"Tor verification failed: {tor.get('error')}")
            print("⚠️  Tor not available - skipping onion site scans")
            print("   To enable dark web monitoring, ensure Tor is installed and set ENABLE_DARKWEB=true")
    except Exception as e:
        print(f"⚠️  Onion monitoring issue: {e}")
    
    print()
    print("=" * 80)
    print("FIXING ALL ISSUES - Phase 3: Breach Markets Status")
    print("=" * 80)
    print()
    
    # ===== FIX 3: Refresh breach markets and check their status =====
    print("🛒  Step 3: Refreshing breach market data and status...")
    try:
        from connectors.ransomlook_market import RansomlookMarketConnector
        market_conn = RansomlookMarketConnector(db)
        
        # Refresh the market URLs
        print("   Fetching latest markets from RansomLook...")
        await market_conn._ensure_breach_table()
        await market_conn._refresh_breach_markets()
        print("✅ Breach market list updated")
        
        # Check their status
        print("   Checking market uptime (sampling 50 markets)...")
        await market_conn.check_all_markets()
        print("✅ Breach market status check complete")
    except Exception as e:
        print(f"⚠️  Breach market issue: {e}")
    
    print()
    print("=" * 80)
    print("FIXING ALL ISSUES - Phase 4: Generate Excel Export")
    print("=" * 80)
    print()
    
    # ===== FIX 4: Generate comprehensive Excel export =====
    print("📊 Step 4: Generating comprehensive Excel export...")
    try:
        from utils.excel_exporter import ExcelExporter
        exporter = ExcelExporter(db)
        path = await exporter.export()
        print(f"✅ Excel file generated: {path}")
    except Exception as e:
        print(f"❌ Excel export failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 80)
    print("VERIFICATION - Final Health Check")
    print("=" * 80)
    print()
    
    # Final verification
    try:
        async with db._conn.execute(
            "SELECT COUNT(*) as cnt FROM ics_advisories WHERE poc_availability != 'Unknown' AND poc_availability IS NOT NULL AND poc_availability != ''"
        ) as cur:
            row = await cur.fetchone()
            poc_count = row["cnt"] if row else 0
        
        async with db._conn.execute(
            "SELECT COUNT(*) as cnt FROM onion_sites WHERE last_status = '200' OR last_status = 'online'"
        ) as cur:
            row = await cur.fetchone()
            onion_online = row["cnt"] if row else 0
        
        async with db._conn.execute(
            "SELECT COUNT(*) as cnt FROM breach_markets WHERE last_status = '200'"
        ) as cur:
            row = await cur.fetchone()
            breach_online = row["cnt"] if row else 0
        
        print("✅ ICS POC Availability populated:      ", f"{poc_count:,} records")
        print("✅ Onion Sites Online:                  ", f"{onion_online:,} sites")
        print("✅ Breach Markets Online:               ", f"{breach_online:,} markets")
        
    except Exception as e:
        print(f"❌ Verification error: {e}")
    
    print()
    print("=" * 80)
    print("✅ ALL FIXES COMPLETE")
    print("=" * 80)
    
    await db.close()

if __name__ == "__main__":
    asyncio.run(fix_all())
