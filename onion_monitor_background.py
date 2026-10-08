#!/usr/bin/env python3
"""
Auto-run onion monitor in background every 30 minutes.
This script is intended to be run via the scheduler (already configured).
"""
import asyncio
import logging
from datetime import datetime
from database.db import Database
from connectors.onion_monitor import OnionMonitorConnector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

async def run_onion_monitor_background():
    """
    Continuous background monitoring with automatic restarts.
    Runs every 30 minutes via scheduler.
    """
    db = Database()
    await db.initialize()
    
    try:
        logger.info("=" * 80)
        logger.info("🕷️  ONION MONITOR - Background Scan Started")
        logger.info("=" * 80)
        
        # Get counts before
        total_before = await db._query_val('SELECT COUNT(*) FROM onion_sites')
        online_before = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status = '200'")
        
        logger.info(f"Starting with {total_before:,} configured sites, {online_before:,} currently online")
        
        # Run the monitor
        monitor = OnionMonitorConnector(db)
        await monitor.run()
        
        # Get counts after
        online_after = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status = '200'")
        offline_after = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE last_status IS NOT NULL AND last_status != '200' AND last_status != 'pending'")
        
        logger.info("=" * 80)
        logger.info("🕷️  ONION MONITOR - Scan Complete")
        logger.info("=" * 80)
        logger.info(f"  📊 Online sites: {online_after:,}")
        logger.info(f"  📊 Offline/Error: {offline_after:,}")
        logger.info(f"  📊 Total checked: {online_after + offline_after:,}")
        
        # Get latest screenshot count
        ss_count = await db._query_val("SELECT COUNT(*) FROM onion_sites WHERE screenshot_path IS NOT NULL")
        logger.info(f"  📷 Screenshots captured: {ss_count:,}")
        
        # Show top online sites
        async with db._conn.execute(
            "SELECT group_name, url FROM onion_sites WHERE last_status = '200' ORDER BY last_checked DESC LIMIT 3"
        ) as cur:
            top_online = await cur.fetchall()
            if top_online:
                logger.info(f"  🟢 Top Active Sites:")
                for site in top_online:
                    logger.info(f"     • {site['group_name']}: {site['url'][:50]}")
        
        logger.info("✅ Onion monitor background scan completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Onion monitor error: {e}", exc_info=True)
    finally:
        await db.close()

if __name__ == "__main__":
    asyncio.run(run_onion_monitor_background())
