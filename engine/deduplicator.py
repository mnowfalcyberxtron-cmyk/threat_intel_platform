"""engine/deduplicator.py — IOC Deduplication Engine"""
import logging
from urllib.parse import urlparse
from database.db import Database

logger = logging.getLogger("engine.deduplicator")

class IOCDeduplicator:
    def __init__(self, db: Database):
        self.db = db

    async def run_subsumption_sweep(self) -> int:
        """
        Cleans up the database by deduplicating noisy URLs.
        If a malicious domain or IP (e.g. example.com) is already recorded
        as an IOC, this deletes all children URLs (e.g. http://example.com/payload)
        to prevent UI clutter.
        """
        logger.info("[Deduplicator] Starting IOC subsumption sweep...")
        removed_count = 0
        
        try:
            # Get all domains and IPs
            async with self.db._conn.execute(
                "SELECT ioc FROM iocs WHERE ioc_type IN ('domain', 'ip')"
            ) as cur:
                roots = {row["ioc"] for row in await cur.fetchall()}

            if not roots:
                return 0

            # Find all URLs
            async with self.db._conn.execute(
                "SELECT id, ioc FROM iocs WHERE ioc_type = 'url'"
            ) as cur:
                url_rows = await cur.fetchall()

            to_delete = []
            for row in url_rows:
                url = row["ioc"]
                try:
                    # Parse the domain/IP out of the URL
                    if not url.startswith("http"):
                        url = "http://" + url
                    parsed = urlparse(url)
                    netloc = parsed.netloc
                    
                    # strip port if exists
                    if ":" in netloc:
                        netloc = netloc.rsplit(":", 1)[0]
                        
                    if netloc and netloc in roots:
                        to_delete.append(row["id"])
                except Exception:
                    pass

            if to_delete:
                # Delete the redundant URLs
                placeholders = ",".join("?" * len(to_delete))
                await self.db._conn.execute(
                    f"DELETE FROM iocs WHERE id IN ({placeholders})", to_delete
                )
                await self.db._conn.commit()
                removed_count = len(to_delete)
                logger.info(f"[Deduplicator] Subsumed {removed_count} redundant URL IOCs into their root domains/IPs.")

        except Exception as e:
            logger.error(f"[Deduplicator] Execution failed: {e}")
            
        return removed_count

