"""connectors/onion_monitor.py — CyberXTron TIP Onion Monitor Backend
Runs a daily accuracy-first health check of all .onion sites via Tor.
Key behaviour:
- First checks if Tor is reachable at all (via check.torproject.org)
- If Tor is NOT available → ABORT the entire run, touch nothing in DB
- If Tor IS available → check every site accurately (60s timeout per site)
- Alerts when sites go online or offline (status change from previous check)
"""
import asyncio
import logging
import os
from datetime import datetime, timezone
import aiohttp
from aiohttp_socks import ProxyConnector
from playwright.async_api import async_playwright
from database.db import Database
from config import settings

logger = logging.getLogger("connectors.onion_monitor")

TOR_CHECK_URL = "https://check.torproject.org/api/ip"

class OnionMonitorConnector:
    def __init__(self, db: Database):
        self.db = db
        self.name = "onion_monitor"
        self.display_name = "Onion Status Monitor"
        self.tor_proxy = f"socks5://{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}" if settings.ENABLE_DARKWEB else None

    async def _check_tor_available(self) -> bool:
        """Return True if Tor proxy is reachable."""
        if not self.tor_proxy:
            logger.warning("[OnionMonitor] No Tor proxy configured. Set TOR_SOCKS_PORT in .env")
            return False

        try:
            connector = ProxyConnector.from_url(self.tor_proxy)
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(TOR_CHECK_URL) as resp:
                    data = await resp.json()
                    if data.get("IsTor", False):
                        return True
        except Exception as e:
            logger.error(f"[OnionMonitor] Tor check failed: {e}. Check if Tor service is running.")
            return False
            
        return False

    def _format_url(self, url: str) -> str:
        """Ensure URL has http prefix."""
        return url if url.startswith("http") else f"http://{url}"

    async def run(self, pending_only: bool = False):
        """
        Accuracy-first scan. Captures status, metadata, HTML, and screenshots.
        Concurrency is limited to avoid overloading Tor.
        """
        logger.info(f"[OnionMonitor] Starting scan (pending_only={pending_only}) — checking Tor availability...")

        tor_ok = await self._check_tor_available()
        if not tor_ok:
            logger.warning("[OnionMonitor] Tor proxy is not reachable. Aborting scan.")
            return

        # Auto-sync newly discovered .onion sites from victims
        await self.db.sync_discovered_onions()

        where = "WHERE active=1"
        if pending_only:
            where += " AND (last_status = 'pending' OR last_status IS NULL OR last_status = 'None')"

        async with self.db._conn.execute(
            f"SELECT id, group_name, url, last_status FROM onion_sites {where}"
        ) as cur:
            sites = await cur.fetchall()

        if not sites:
            logger.info("[OnionMonitor] No sites to scan in this mode.")
            return

        logger.info(f"[OnionMonitor] Scanning {len(sites)} sites (Concurrency=5)...")
        
        # Ensure screenshot dir exists
        os.makedirs("data/screenshots", exist_ok=True)

        # Concurrency limit
        semaphore = asyncio.Semaphore(5)

        async with async_playwright() as p:
            # Launch chromium with or without Tor proxy
            proxy_cfg = {"server": self.tor_proxy}
            browser = await p.chromium.launch(
                proxy=proxy_cfg,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            context = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
            )
            
            async def bounded_scan(site):
                async with semaphore:
                    site_id, group, url, old_status = site
                    await self._scan_site(context, site_id, group, url, old_status)

            # Run in parallel with semaphore
            await asyncio.gather(*(bounded_scan(s) for s in sites))

            if browser: await browser.close()

        await self.db.update_source_status(self.name, "ok", len(sites))
        logger.info(f"[OnionMonitor] Done. {len(sites)} sites processed.")

    async def run_targeted_scan(self, site_id, victim_name=None):
        """Run a single scan for a specific site, optionally scrolling to a victim."""
        logger.info(f"[OnionMonitor] Starting targeted scan for site_id={site_id}, victim={victim_name}")
        
        tor_ok = await self._check_tor_available()
        if not tor_ok:
            logger.error("[OnionMonitor] Tor not available for targeted scan.")
            return False

        async with self.db._conn.execute(
            "SELECT id, group_name, url, last_status FROM onion_sites WHERE id=?", (site_id,)
        ) as cur:
            site = await cur.fetchone()
        
        if not site:
            logger.error(f"[OnionMonitor] Site {site_id} not found.")
            return False

        site_id, group, url, old_status = site
        
        async with async_playwright() as p:
            browser = None
            try:
                proxy_cfg = {"server": self.tor_proxy}
                browser = await p.chromium.launch(
                    proxy=proxy_cfg,
                    args=["--no-sandbox", "--disable-setuid-sandbox"]
                )
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
                )
                await self._scan_site(context, site_id, group, url, old_status, victim_name)
                return True
            except Exception as e:
                logger.error(f"[OnionMonitor] Targeted scan failed: {e}")
                return False
            finally:
                if browser: await browser.close()

    async def _scan_site(self, context, site_id, group, url, old_status, victim_name=None):
        full_url = self._format_url(url)
        try:
            logger.info(f"[OnionMonitor] Scanning: {group} ({url[:30]}...)")
            page = await context.new_page()
            
            # Set a generous timeout for .onion sites
            response = await page.goto(full_url, timeout=90000, wait_until="domcontentloaded")
            
            if response and response.status < 400:
                # 1. Success! Capture data
                title = await page.title()
                # Extract meta generator
                generator = ""
                try:
                    generator = await page.eval_on_selector(
                        'meta[name="generator"]', "el => el.content"
                    )
                except: pass
                
                # Extract clean text
                content = await page.evaluate("document.body.innerText")
                content = (content or "").strip()[:1000]
                full_html = await page.content()
                
                # --- TARGETTED SCROLLING ---
                if victim_name:
                    logger.info(f"[OnionMonitor] Attempting scroll-to-victim: {victim_name}")
                    try:
                        # Case-insensitive search for the victim name in visible text
                        await page.evaluate(f"""
                            (name) => {{
                                const xpath = `//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), "${victim_name.lower()}")]`;
                                const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                                if (element) {{
                                    element.scrollIntoView({{ behavior: 'instant', block: 'center' }});
                                    element.style.outline = '4px solid #f85149';
                                    element.style.outlineOffset = '4px';
                                }}
                            }}
                        """, victim_name)
                        await page.wait_for_timeout(2000) # Wait for scroll to settle
                    except Exception as scroll_err:
                        logger.warning(f"[OnionMonitor] Scroll failed: {scroll_err}")

                # Capture Screenshot
                ss_filename = f"{group.lower().replace(' ', '_')}_{site_id}_{int(datetime.now().timestamp())}.png"
                ss_path = os.path.join("data/screenshots", ss_filename).replace("\\", "/")
                
                # Robust wait for Tor DDoS Guards & dynamic content
                try:
                    await page.evaluate("document.body.style.backgroundColor = 'white'")
                except Exception:
                    pass

                for _ in range(3):
                    await page.wait_for_timeout(5000)
                    try:
                        text_len = await page.evaluate("document.body.innerText.length")
                        if text_len > 100:
                            break
                    except Exception:
                        pass
                
                await page.screenshot(path=ss_path, full_page=False)
                
                # Update DB
                await self.db.update_onion_scrape(site_id, title, generator, content, full_html, ss_path)
                
                # Status change alerts
                if old_status != "200":
                    await self._alert_status(group, url, old_status, "200", True)
            
            else:
                status_code = str(response.status if response else "failed")
                await self._update_basic_status(site_id, status_code)
                if old_status == "200":
                    await self._alert_status(group, url, old_status, status_code, False)

            await page.close()

        except Exception as e:
            logger.debug(f"[OnionMonitor] Playwright failed for {url}: {e}")
            if not victim_name: # Don't fallback for targeted scans
                await self._fallback_check(site_id, group, url, old_status)

    async def _fallback_check(self, site_id, group, url, old_status):
        """Simple aiohttp check if browser fails."""
        try:
            connector = ProxyConnector.from_url(self.tor_proxy)
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=45)) as session:
                full_url = self._format_url(url)
                async with session.get(full_url) as resp:
                    new_status = str(resp.status)
                    is_online = resp.status < 400
                    await self._update_basic_status(site_id, new_status)
                    if (old_status == "200") != is_online:
                        await self._alert_status(group, url, old_status, new_status, is_online)
        except:
            await self._update_basic_status(site_id, "offline/timeout")
            if old_status == "200":
                await self._alert_status(group, url, old_status, "offline/timeout", False)

    async def _update_basic_status(self, site_id, status):
        now = datetime.now(timezone.utc).isoformat()
        await self.db._conn.execute(
            "UPDATE onion_sites SET last_checked=?, last_status=? WHERE id=?",
            (now, status, site_id)
        )
        await self.db._conn.commit()

    async def _alert_status(self, group, url, old_status, new_status, is_online):
        severity = "medium" if is_online else "high"
        title = f"Ransomware Site {'ONLINE' if is_online else 'OFFLINE'}: {group}"
        msg = f"{group} status change: {url} ({old_status} -> {new_status})"
        
        await self.db.create_alert({
            "alert_type": "onion_status_change",
            "title": title,
            "description": msg,
            "severity": severity,
            "source": "Onion Monitor"
        })
