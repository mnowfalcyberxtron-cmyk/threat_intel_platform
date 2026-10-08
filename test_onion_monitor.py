#!/usr/bin/env python3
"""Manual trigger for onion site monitoring to test the fixes."""
import asyncio
import logging
from database.db import Database
from connectors.onion_monitor import OnionMonitorConnector

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

async def main():
    print("\n" + "=" * 90)
    print("🕷️  TESTING ONION MONITOR - Manual Trigger")
    print("=" * 90)
    print()
    
    db = Database()
    await db.initialize()
    
    try:
        # Check total configured sites
        total = await db._query_val("SELECT COUNT(*) FROM onion_sites")
        print(f"📊 Total .onion sites configured: {total:,}")
        
        # Show a few pending/never-scanned sites
        async with db._conn.execute(
            "SELECT id, group_name, url FROM onion_sites WHERE last_status IS NULL OR last_status = 'pending' LIMIT 3"
        ) as cur:
            pending = await cur.fetchall()
            if pending:
                print(f"📋 Sample pending sites:")
                for site in pending:
                    print(f"   • {site['group_name']}: {site['url'][:50]}")
        print()
        
        print("▶️  Starting onion monitor scan...")
        print("   (This will test Tor connectivity and scan onion sites)")
        print("   (Concurrency: 5 sites at a time)")
        print()
        
        monitor = OnionMonitorConnector(db)
        
        # Run the monitor
        await monitor.run()
        
        print()
        print("✅ Onion monitor scan completed!")
        print()
        
        # Check updated statistics
        total = await db._query_val("SELECT COUNT(*) FROM onion_sites")
        online = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status = '200'")
        offline = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status IS NOT NULL AND last_status != '200' AND last_status != 'pending'")
        pending = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status IS NULL OR last_status = 'pending'")
        
        print("📊 UPDATED STATUS:")
        print(f"   Total:    {total:,}")
        print(f"   🟢 Online: {online:,} ({100*online/(total or 1):.1f}%)")
        print(f"   🔴 Offline: {offline:,} ({100*offline/(total or 1):.1f}%)")
        print(f"   ⏳ Pending: {pending:,} ({100*pending/(total or 1):.1f}%)")
        print()
        
        # Check status history entries
        hist_count = await db._query_val("SELECT COUNT(*) FROM status_history WHERE target_type = 'onion_site'")
        print(f"📝 Status history entries: {hist_count:,}")
        print()
        
        # Show sample results
        async with db._conn.execute(
            "SELECT url, last_status, last_checked FROM onion_sites WHERE last_status IS NOT NULL ORDER BY last_checked DESC LIMIT 5"
        ) as cur:
            results = await cur.fetchall()
            if results:
                print("🔍 Recent scan results:")
                for r in results:
                    status_emoji = "🟢" if r['last_status'] == '200' else "🔴"
                    print(f"   {status_emoji} {r['url'][:50]:50} | {r['last_status']:15} | {r['last_checked']}")
        print()
        
        print("=" * 90)
        print("✨ NEXT STEPS:")
        print("=" * 90)
        print()
        print("1. The onion monitor is configured to run AUTOMATICALLY every 30 minutes")
        print("2. Check the UI: 🌑 Dark Web Manager to see updated status badges")
        print("3. Status will show: ● ACTIVE | ◌ PENDING | ✗ OFFLINE")
        print()
        print("📍 MONITOR STATUS:")
        if online > 0:
            print(f"   ✅ SUCCESS! Found {online} online .onion sites!")
            print("   Screenshots being captured for active sites")
            print("   Status history is being logged for tracking")
        elif offline > 0:
            print(f"   ✓ Scan working! {offline} sites checked but offline")
            print("   This is normal - many .onion markets go down frequently")
        else:
            print("   ⚠️  All sites showing pending - scan may still be running")
            print("   Check logs for connectivity issues with Tor")
        print()
        
    except Exception as e:
        logger.error(f"❌ Error: {e}", exc_info=True)
    finally:
        await db.close()

if __name__ == "__main__":
    asyncio.run(main())
