import asyncio
import sys
import os
import logging

# Add current dir to sys.path
sys.path.append(os.getcwd())

from database.db import Database
from connectors.onion_monitor import OnionMonitorConnector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_scrape")

async def run():
    db = Database()
    await db.initialize()
    
    # Ensure our test site is there
    await db._conn.execute(
        "INSERT OR IGNORE INTO onion_sites (group_name, url) VALUES (?, ?)",
        ("TestTorCheck", "https://check.torproject.org/")
    )
    await db._conn.commit()
    
    # Run the monitor!
    monitor = OnionMonitorConnector(db)
    logger.info("Starting OnionMonitor deep scan check...")
    await monitor.run()
    
    # Check if data was captured
    async with db._conn.execute(
        "SELECT group_name, page_title, screenshot_path, length(full_html) as html_len FROM onion_sites WHERE url LIKE '%torproject%'"
    ) as cur:
        row = await cur.fetchone()
        if row:
            logger.info(f"Captured for {row['group_name']}: Title: {row['page_title']}, SS: {row['screenshot_path']}, HTML Size: {row['html_len']}")
        else:
            logger.warning("No data captured for test site.")
            
    await db.close()

if __name__ == "__main__":
    asyncio.run(run())
