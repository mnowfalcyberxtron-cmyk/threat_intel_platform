"""engine/scheduler.py — v2.3 with web intel every 5 minutes."""
import asyncio
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from config import settings
from database.db import Database
from engine.processor import IOCProcessor
from engine.alerting import AlertingEngine

logger = logging.getLogger("engine.scheduler")


class MonitoringScheduler:
    def __init__(self, db: Database):
        self.db        = db
        self.processor = IOCProcessor(db)
        self.alerting  = AlertingEngine(db)
        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._running   = False

    def start(self):
        self._register_jobs()
        self._scheduler.start()
        self._running = True
        logger.info("Scheduler started — %d jobs", len(self._scheduler.get_jobs()))

    def stop(self):
        if self._running:
            self._scheduler.shutdown(wait=False)
            self._running = False

    def _register_jobs(self):
        from connectors.urlhaus         import URLHausConnector
        from connectors.threatfox       import ThreatFoxConnector
        from connectors.feodo           import FeodoConnector
        from connectors.malwarebazaar   import MalwareBazaarConnector
        from connectors.ransomware_live import RansomwareLiveConnector
        from connectors.circl_osint     import CIRCLOSINTConnector
        from connectors.rss_feeds       import RSSFeedsConnector
        from connectors.github_intel    import GitHubIntelConnector
        from connectors.haveibeenransom import HaveIBeenRansomConnector
        from connectors.falconfeeds     import FalconFeedsConnector
        from connectors.hibp            import HIBPConnector
        from connectors.hibr            import HIBRConnector
        from connectors.darkweb         import DarkWebConnector
        from connectors.ransomlook_market import RansomlookMarketConnector
        from connectors.telegram_monitor import TelegramMonitorConnector

        ioc_jobs = [
            (ThreatFoxConnector,       "threatfox",       settings.THREATFOX_INTERVAL,     True),
            (URLHausConnector,         "urlhaus",         settings.URLHAUS_INTERVAL,        True),
            (FeodoConnector,           "feodo",           settings.FEODO_INTERVAL,           True),
            (MalwareBazaarConnector,   "malwarebazaar",   settings.MALWAREBAZAAR_INTERVAL,  True),
            (RansomwareLiveConnector,  "ransomware_live", settings.RANSOMWARE_INTERVAL,     True),
            (RansomlookMarketConnector,"ransomlook_market", settings.RANSOMWARE_INTERVAL,   True),
            (TelegramMonitorConnector,  "telegram_monitor",  settings.RANSOMWARE_INTERVAL,   True),
            (HaveIBeenRansomConnector, "haveibeenransom", settings.RANSOMWARE_INTERVAL,     True),
            (CIRCLOSINTConnector,      "circl_osint",     settings.CIRCL_INTERVAL,          True),
            (RSSFeedsConnector,        "rss",             settings.RSS_INTERVAL,             True),
            (GitHubIntelConnector,     "github_intel",    settings.GITHUB_INTERVAL,          True),
            (HIBRConnector,            "hibr",            settings.HIBR_INTERVAL,            settings.ENABLE_HIBR),
            (FalconFeedsConnector,     "falconfeeds",     settings.FALCONFEEDS_INTERVAL,     settings.ENABLE_FALCONFEEDS),
            (HIBPConnector,            "hibp",            7200,                               settings.ENABLE_HIBP),
            (DarkWebConnector,         "darkweb",         settings.DARKWEB_INTERVAL,         settings.ENABLE_DARKWEB),
        ]
        
        # Periodic Onion Discovery Sync — every 30 minutes
        self._scheduler.add_job(
            func=self._run_onion_sync,
            trigger=IntervalTrigger(minutes=30),
            id="onion_sync", name="Onion Discovery Sync",
            replace_existing=True, max_instances=1,
        )
        logger.info("  [+] onion_sync - every 30 min")
        for cls, jid, interval, enabled in ioc_jobs:
            if not enabled: logger.info("  [-] %s - disabled", jid); continue
            self._scheduler.add_job(
                func=self._run_connector, trigger=IntervalTrigger(seconds=interval),
                kwargs={"connector_cls": cls}, id=jid, name=jid.replace("_"," ").title(),
                replace_existing=True, max_instances=1, misfire_grace_time=300,
            )
            logger.info("  [+] %s - every %ds", jid, interval)

        # Web Intel — runs every 5 minutes, separate processing
        self._scheduler.add_job(
            func=self._run_web_intel,
            trigger=IntervalTrigger(seconds=300),
            id="web_intel", name="Web Intel Feed",
            replace_existing=True, max_instances=1, misfire_grace_time=60,
        )
        logger.info("  [+] web_intel - every 300s (5 min)")

        # Feed cleanup — daily
        self._scheduler.add_job(
            func=self._cleanup_feed,
            trigger=IntervalTrigger(hours=12),
            id="feed_cleanup", name="Feed Cleanup",
            replace_existing=True, max_instances=1,
        )

        # Advisory monitor — every 30 minutes
        self._scheduler.add_job(
            func=self._run_advisory_monitor,
            trigger=IntervalTrigger(minutes=30),
            id="advisory_monitor", name="Advisory Monitor",
            replace_existing=True, max_instances=1, misfire_grace_time=300,
        )
        logger.info("  [+] advisory_monitor - every 30 min")

        # Onion Monitor — daily at 4:00 PM IST (Asia/Kolkata)
        self._scheduler.add_job(
            func=self._run_onion_monitor,
            trigger=CronTrigger(hour=16, minute=0, timezone="Asia/Kolkata"),
            id="onion_monitor", name="Onion Status Monitor (Daily 4PM IST)",
            replace_existing=True, max_instances=1, misfire_grace_time=1800,
        )
        logger.info("  [+] onion_monitor - daily at 16:00 IST / 10:30 UTC")
        
        # Social Media Monitor — every 60 minutes
        self._scheduler.add_job(
            func=self._run_social_monitor,
            trigger=IntervalTrigger(minutes=60),
            id="social_monitor", name="Social Media Threat Monitor",
            replace_existing=True, max_instances=1, misfire_grace_time=300,
        )
        logger.info("  [+] social_monitor - every 60 min")
        
        # IOC Validation Sweep — every 6 hours
        self._scheduler.add_job(
            func=self._run_ioc_validation,
            trigger=IntervalTrigger(hours=6),
            id="ioc_validation", name="Automated IOC Validation Sweep",
            replace_existing=True, max_instances=1,
        )
        logger.info("  [+] ioc_validation - every 6 hours")

    async def _run_social_monitor(self) -> None:
        """Fetch threat intel from social media (X/LinkedIn)."""
        from connectors.social_monitor import SocialMonitorConnector
        conn = SocialMonitorConnector(self.db)
        try:
            await conn.run()
        except Exception as e:
            logger.error("[ERR] social_monitor: %s", e)
            await self.db.update_source_status("social_monitor", "error", error_msg=str(e)[:200])

    async def _run_onion_monitor(self) -> None:
        """Run the backend monitor for .onion sites."""
        from connectors.onion_monitor import OnionMonitorConnector
        from connectors.telegram_monitor import TelegramMonitorConnector
        conn = OnionMonitorConnector(self.db)
        try:
            await conn.run()
        except Exception as e:
            logger.error("[ERR] onion_monitor: %s", e)
            await self.db.update_source_status("onion_monitor", "error", error_msg=str(e)[:200])

    async def _run_onion_sync(self) -> None:
        """Automated onion discovery from victim reports."""
        try:
            await self.db.sync_discovered_onions()
        except Exception as e:
            logger.debug("Onion sync error: %s", e)

    async def _run_connector(self, connector_cls) -> None:
        import inspect
        sig = inspect.signature(connector_cls.__init__)
        if "db" in sig.parameters:
            connector = connector_cls(db=self.db)
        else:
            connector = connector_cls()
            
        src = connector.name
        try:
            logger.info("[RUN] %s", connector.display_name)
            records = await connector.run()
            if not records:
                await self.db.update_source_status(src, "ok", 0); return
            stats = await self.processor.process_batch(records, src)
            total = stats.get("new",0) + stats.get("updated",0)
            await self.db.update_source_status(src, "ok", total)
            await self.db.log("INFO", src,
                f"+{stats.get('new',0)} new | {stats.get('updated',0)} updated | "
                f"{stats.get('victims_new',0)} new victims")
            logger.info("  [OK] %s: +%d new | %d updated | %d victims",
                src, stats["new"], stats["updated"], stats.get("victims_new",0))
        except Exception as e:
            logger.error("[ERR] %s: %s", src, e, exc_info=True)
            await self.db.update_source_status(src, "error", error_msg=str(e)[:200])
            await self.db.log("ERROR", src, f"Failed: {str(e)[:200]}")

    async def _run_web_intel(self) -> None:
        """Run WebIntelConnector and store results in threat_feed table."""
        from connectors.web_intel import WebIntelConnector
        connector = WebIntelConnector()
        try:
            records = await connector.run()
            new_count = 0
            for rec in records:
                if rec.get("type") == "feed_item":
                    _, is_new = await self.db.upsert_feed_item(rec)
                    if is_new: new_count += 1
            await self.db.update_source_status("web_intel", "ok", new_count)
            if new_count > 0:
                await self.db.log("INFO", "web_intel",
                    f"+{new_count} new threat intel items from web sources")
                logger.info("  [OK] web_intel: +%d new feed items", new_count)
        except Exception as e:
            logger.error("[ERR] web_intel: %s", e)
            await self.db.update_source_status("web_intel", "error", error_msg=str(e)[:200])

    async def _cleanup_feed(self) -> None:
        """Remove old feed items and deduplicate IOCs to keep DB lean."""
        try:
            await self.db.clean_old_feed(hours=72)
            
            # Run deduplication
            from engine.deduplicator import IOCDeduplicator
            dedup = IOCDeduplicator(self.db)
            await dedup.run_subsumption_sweep()
            
            # Also run a validation sweep during cleanup
            await self._run_ioc_validation()
            
            logger.info("Feed cleanup and Deduplication complete")
        except Exception as e:
            logger.debug("Cleanup/Deduplication error: %s", e)

    async def _run_ioc_validation(self) -> None:
        """Run the automated validation and cleanup sweep."""
        from engine.validator import IOCValidator
        validator = IOCValidator(self.db)
        try:
            await validator.run_cleanup_sweep()
        except Exception as e:
            logger.error("[ERR] ioc_validation: %s", e)

    async def _run_advisory_monitor(self) -> None:
        """Fetch Top 25 company advisories."""
        from connectors.advisory_monitor import AdvisoryMonitorConnector
        conn = AdvisoryMonitorConnector()
        try:
            records = await conn.run()
            new_count = 0
            for rec in records:
                if rec.get("type") == "advisory":
                    _, is_new = await self.db.upsert_advisory(rec)
                    if is_new: new_count += 1
            await self.db.update_source_status("advisory_monitor", "ok", new_count)
            if new_count > 0:
                await self.db.log("INFO","advisory_monitor",f"+{new_count} new advisories from Top 25 companies")
                logger.info("  [OK] advisory_monitor: +%d new advisories", new_count)
        except Exception as e:
            logger.error("[ERR] advisory_monitor: %s", e)
            await self.db.update_source_status("advisory_monitor","error",error_msg=str(e)[:200])

    async def run_all_now(self) -> dict:
        from connectors.urlhaus         import URLHausConnector
        from connectors.threatfox       import ThreatFoxConnector
        from connectors.feodo           import FeodoConnector
        from connectors.malwarebazaar   import MalwareBazaarConnector
        from connectors.ransomware_live import RansomwareLiveConnector
        from connectors.circl_osint     import CIRCLOSINTConnector
        from connectors.haveibeenransom import HaveIBeenRansomConnector
        from connectors.ransomlook_market import RansomlookMarketConnector

        logger.info("[RELOAD] Running all connectors + web intel...")
        # Tier 1 + web intel in parallel
        tier1 = [ThreatFoxConnector, URLHausConnector, FeodoConnector,
                 MalwareBazaarConnector, RansomwareLiveConnector,
                 HaveIBeenRansomConnector, CIRCLOSINTConnector,
                 RansomlookMarketConnector]
        tasks = [self._run_connector(c) for c in tier1] + [self._run_web_intel(), self._run_social_monitor()]
        await asyncio.gather(*tasks, return_exceptions=True)

        from connectors.rss_feeds    import RSSFeedsConnector
        from connectors.github_intel import GitHubIntelConnector
        for cls in [RSSFeedsConnector, GitHubIntelConnector]:
            try: await self._run_connector(cls)
            except Exception: pass

        # Run advisory monitor on startup
        try: await self._run_advisory_monitor()
        except Exception: pass

        # Run onion monitor
        try: await self._run_onion_sync()
        except Exception: pass
        try: await self._run_onion_monitor()
        except Exception: pass

        if settings.ENABLE_HIBR:
            from connectors.hibr import HIBRConnector
            try: await self._run_connector(HIBRConnector)
            except Exception: pass
        if settings.ENABLE_DARKWEB:
            from connectors.darkweb import DarkWebConnector
            try: await self._run_connector(DarkWebConnector)
            except Exception: pass

        # Run IOC validation on startup
        try: await self._run_ioc_validation()
        except Exception: pass

        await self.alerting.generate_startup_alerts(self.db)
        return {"status": "complete"}

    def get_job_status(self):
        return [{"id": j.id, "name": j.name,
                 "next_run": j.next_run_time.isoformat() if j.next_run_time else None}
                for j in self._scheduler.get_jobs()]
