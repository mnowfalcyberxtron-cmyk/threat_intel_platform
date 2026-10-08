import asyncio
import sys
import logging
import os
from datetime import datetime, timezone, timedelta
sys.path.insert(0, '.')

from database.db import Database
from config import settings
from connectors.cvelist_enrichment import _GitHubPoller

logging.basicConfig(level=logging.DEBUG)

async def test_live_sync():
    db = Database()
    await db.initialize()
    
    # Force the "last_checked" time to 12 hours ago to ensure we find commits
    poller = _GitHubPoller(github_token=settings.GITHUB_TOKEN)
    twelve_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    poller._last_checked = twelve_hours_ago
    
    print(f"Polling GitHub API for changes since {twelve_hours_ago}...")
    try:
        updated, new_enriched = await poller.poll_once(db)
        print(f"SUCCESS: {updated} ICS rows updated from GitHub commits, {new_enriched} new pending rows enriched.")
    except Exception as e:
        print(f"FAILED: {e}")
        
    await db.close()

asyncio.run(test_live_sync())
