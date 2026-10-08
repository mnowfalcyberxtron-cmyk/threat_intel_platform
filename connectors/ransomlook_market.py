"""
connectors/ransomlook_market.py — Breach Market intelligence from Ransomlook.io
Fetches all tracked market/forum/breach site URLs and persists them to breach_markets.
Runs uptime checks on clearnet URLs via direct HTTP.
"""
import asyncio
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector
from config import settings

logger = logging.getLogger("connector.ransomlook_market")


class RansomlookMarketConnector(BaseConnector):
    name = "ransomlook_market"
    display_name = "RansomLook Breach Market Monitor"
    tier = 1

    # Public endpoints
    GROUPS_URL    = "https://www.ransomlook.io/api/groups"
    CSV_URL       = "https://www.ransomlook.io/urls.csv"
    VICTIMS_URL   = "https://www.ransomlook.io/api/victims/recent"
    RSS_URL       = "https://www.ransomlook.io/rss.xml"

    def __init__(self, db=None):
        super().__init__()
        self.db = db

    async def fetch(self) -> List[Dict[str, Any]]:
        """
        Main sync task.
        1. Pull breach market URLs and upsert into breach_markets.
        2. Pull recent victims (JSON + RSS) and return them as normalized records.
        """
        await self._ensure_breach_table()
        await self._refresh_breach_markets()
        
        # Trigger background uptime check for all markets (Continuous monitoring)
        asyncio.create_task(self.check_all_markets())
        
        # Combine JSON and RSS victims for continuous improvement
        rss_records  = await self._fetch_recent_victims_rss()
        
        # Deduplicate by victim name and group
        seen = set()
        combined = []
        for r in rss_records:
            key = f"{r.get('victim_name')}|{r.get('group_name')}".lower()
            if key not in seen:
                seen.add(key)
                combined.append(r)
        
        return combined

    # ── Internal helpers ────────────────────────────────────────────────────────

    async def _ensure_breach_table(self):
        """Create breach_markets table if it doesn't exist."""
        try:
            db = self._get_db()
            if db is None:
                return
            await db._conn.execute("""
                CREATE TABLE IF NOT EXISTS breach_markets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL,
                    url         TEXT NOT NULL UNIQUE,
                    description TEXT DEFAULT '',
                    site_type   TEXT DEFAULT 'market',
                    source      TEXT DEFAULT 'ransomlook',
                    active      INTEGER DEFAULT 1,
                    last_status TEXT DEFAULT 'pending',
                    last_checked TEXT DEFAULT NULL,
                    screenshot_path TEXT DEFAULT '',
                    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            # Ensure columns exist for older versions
            for col, defn in [
                ("screenshot_path", "TEXT DEFAULT ''"),
                ("source", "TEXT DEFAULT 'ransomlook'"),
                ("description", "TEXT DEFAULT ''"),
            ]:
                try:
                    await db._conn.execute(f"ALTER TABLE breach_markets ADD COLUMN {col} {defn}")
                except Exception:
                    pass
            await db._conn.commit()
        except Exception as e:
            logger.warning("Could not ensure breach_markets table: %s", e)

    def _get_db(self):
        """Get DB instance, preferring the one passed in constructor."""
        if self.db:
            return self.db
        try:
            from api.breach_routes import get_db
            return get_db()
        except Exception:
            return None

    async def _refresh_breach_markets(self):
        """Fetch all market URLs from ransomlook.io and upsert into breach_markets."""
        db = self._get_db()
        if db is None:
            logger.warning("DB not available — skipping breach market refresh")
            return

        markets = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as sess:
                async with sess.get(self.CSV_URL, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        lines = text.splitlines()
                        if lines:
                            header = [h.strip().strip('"') for h in lines[0].split(",")]
                            for line in lines[1:]:
                                parts = [p.strip().strip('"') for p in line.split(",")]
                                row = dict(zip(header, parts))
                                name = (row.get("name") or row.get("group") or row.get("Name") or "").strip()
                                url  = (row.get("url")  or row.get("fqdn") or row.get("URL")  or "").strip()
                                s_type = row.get("type", "market").lower()
                                if name and url:
                                    if not url.startswith(("http://", "https://")):
                                        url = f"http://{url}" if ".onion" in url.lower() else f"https://{url}"
                                    markets.append({
                                        "name": name, "url": url,
                                        "site_type": s_type, "description": "",
                                    })
        except Exception as csv_e:
            logger.error("CSV fetch failed: %s", csv_e)

        if not markets:
            logger.info("No breach market URLs retrieved this cycle")
            return

        logger.info("RansomLook: upserting %d market URLs", len(markets))
        inserted = 0
        updated = 0
        onion_synced = 0
        for m in markets:
            try:
                cur = await db._conn.execute(
                    """INSERT INTO breach_markets (name, url, description, site_type, source, active, last_status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 'ransomlook', 1, 'pending', datetime('now'), datetime('now'))
                       ON CONFLICT(url) DO UPDATE SET
                         name        = excluded.name,
                         site_type   = COALESCE(excluded.site_type, site_type),
                         description = CASE WHEN excluded.description != '' THEN excluded.description ELSE description END,
                         updated_at  = datetime('now')""",
                    (m["name"], m["url"], m["description"], m["site_type"]),
                )
                if cur.lastrowid and cur.rowcount:
                    inserted += 1
                else:
                    updated += 1
                if ".onion" in m["url"].lower():
                    onion_cur = await db._conn.execute(
                        """INSERT INTO onion_sites (group_name, url, description, site_type, active, last_status)
                           VALUES (?, ?, 'Discovered from ransomlook.io', 'ransomware', 1, 'pending')
                           ON CONFLICT(url) DO UPDATE SET
                             group_name=COALESCE(NULLIF(excluded.group_name,''), group_name),
                             description=CASE WHEN description IS NULL OR description='' THEN excluded.description ELSE description END,
                             active=1""",
                        (m["name"], m["url"]),
                    )
                    if onion_cur.rowcount > 0:
                        onion_synced += 1
            except Exception as ue:
                logger.debug("Upsert %s: %s", m["url"], ue)
        
        await db._conn.commit()
        if onion_synced:
            logger.info("RansomLook: synced %d .onion URLs into Dark Web Manager", onion_synced)
        if inserted > 0:
            await db.log("INFO", "ransomlook_market", f"Updated {len(markets)} markets (+{inserted} new)")

    async def _fetch_recent_victims_json(self) -> List[Dict[str, Any]]:
        """Fetch recent victims from ransomlook JSON API."""
        records = []
        try:
            data = await self._get(self.VICTIMS_URL)
            if isinstance(data, list):
                for v in data[:300]:
                    if not isinstance(v, dict): continue
                    name  = (v.get("post_title") or v.get("victim") or "").strip()
                    group = (v.get("group_name") or "unknown").strip()
                    if not name: continue
                    records.append(self.make_victim(
                        source=self.name,
                        group_name=group,
                        victim_name=name,
                        description=(v.get("description") or "")[:400],
                        country=(v.get("country") or "").upper()[:3],
                        industry=(v.get("activity") or "Data Breach"),
                        website=(v.get("website") or ""),
                        leak_date=str(v.get("published") or ""),
                        source_url=(v.get("post_url") or ""),
                    ))
        except Exception as e:
            logger.error("RansomLook JSON victims failed: %s", e)
        return records

    async def _fetch_recent_victims_rss(self) -> List[Dict[str, Any]]:
        """Fetch recent victims from ransomlook RSS feed (Continuous Improvement)."""
        records = []
        try:
            import feedparser
            text = await self._get(self.RSS_URL)
            if not text or not isinstance(text, str):
                return []
            
            feed = feedparser.parse(text)
            for entry in feed.entries:
                title = getattr(entry, "title", "") # Usually "Group Name - Victim Name"
                link  = getattr(entry, "link", "")
                summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
                published = getattr(entry, "published", "")
                
                # RansomLook RSS title format is often "GroupName -> VictimName" or just "VictimName"
                group = "unknown"
                victim = title
                if " -> " in title:
                    parts = title.split(" -> ", 1)
                    group = parts[0].strip()
                    victim = parts[1].strip()
                elif " - " in title:
                    parts = title.split(" - ", 1)
                    group = parts[0].strip()
                    victim = parts[1].strip()

                records.append(self.make_victim(
                    source=f"{self.name}_rss",
                    group_name=group,
                    victim_name=victim,
                    description=summary[:400],
                    leak_date=published,
                    source_url=link,
                ))
        except Exception as e:
            logger.warning("RansomLook RSS feed failed: %s", e)
        return records

    async def check_all_markets(self):
        """Check live HTTP status of all clearnet breach markets in DB and capture screenshots."""
        db = self._get_db()
        if db is None: return
        
        async with db._conn.execute("SELECT id, url, name, screenshot_path FROM breach_markets WHERE active=1") as cur:
            rows = await cur.fetchall()

        if not rows: return
        
        logger.info("[RansomLook] Auto-checking uptime for %d breach markets", len(rows))
        semaphore = asyncio.Semaphore(5) # Lower concurrency for screenshots
        
        async def _check_one(row):
            async with semaphore:
                import time as _time
                t0 = _time.monotonic()
                status_code, error_msg = await self._check_url_robust(row["url"])
                latency_ms = int((_time.monotonic() - t0) * 1000)
                is_online  = status_code == 200
                val = str(status_code) if status_code else f"error:{error_msg[:40]}"

                screenshot_path = row["screenshot_path"]
                needs_screenshot = False
                if not screenshot_path:
                    needs_screenshot = True
                else:
                    import time
                    from pathlib import Path
                    local_path = Path("data") / screenshot_path.lstrip('/')
                    if not local_path.exists():
                        needs_screenshot = True
                    elif time.time() - local_path.stat().st_mtime > 86400:
                        needs_screenshot = True

                if status_code == 200 and needs_screenshot:
                    try:
                        new_path = await self._capture_screenshot(row["url"], row["id"])
                        if new_path:
                            screenshot_path = new_path
                    except Exception as se:
                        logger.debug(f"Screenshot failed for {row['url']}: {se}")

                await db._conn.execute(
                    "UPDATE breach_markets SET last_status=?, last_checked=datetime('now'), updated_at=datetime('now'), screenshot_path=? WHERE id=?",
                    (val, screenshot_path, row["id"]),
                )

                # ── Log to status_history for uptime pattern analysis ─────────
                try:
                    await db.add_status_history(
                        target_type="breach_market",
                        target_id=row["id"],
                        name=row["name"],
                        url=row["url"],
                        status="online" if is_online else ("timeout" if not status_code else "offline"),
                        latency_ms=latency_ms if is_online else None,
                    )
                except Exception:
                    pass
        
        tasks = [_check_one(r) for r in rows]
        await asyncio.gather(*tasks, return_exceptions=True)
        await db._conn.commit()
        await db.log("INFO", "ransomlook_market", f"Auto-uptime + screenshot check complete: {len(rows)} markets")

    async def _check_url_robust(self, url: str):
        """Robust HTTP check with HEAD fallback to GET."""
        import aiohttp
        try:
            # Ensure URL has http/https prefix
            if not url.startswith("http://") and not url.startswith("https://"):
                url = f"http://{url}"

            timeout = aiohttp.ClientTimeout(total=20)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            
            # Use Tor if it's an onion address
            is_onion = ".onion" in url.lower()
            connector = None
            if is_onion:
                try:
                    from utils.tor_manager import ensure_tor_proxy
                    tor = await ensure_tor_proxy(settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT)
                    if not tor.get("ok"):
                        return None, tor.get("error", "Tor proxy is not verified")[:80]
                    tor_proxy = tor["proxy_url"]
                except Exception as tor_err:
                    logger.warning("Could not verify Tor in breach check: %s", tor_err)
                    return None, str(tor_err)[:80]
                from aiohttp_socks import ProxyConnector
                # KEY FIX: socks5 proxy with rdns=True resolves DNS through Tor for .onion hostnames
                connector = ProxyConnector.from_url(
                    tor_proxy,
                    rdns=True
                )
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
                try:
                    async with sess.head(url, headers=headers, allow_redirects=True, ssl=False) as resp:
                        return resp.status, ""
                except Exception:
                    async with sess.get(url, headers=headers, allow_redirects=True, ssl=False) as resp:
                        return resp.status, ""
        except asyncio.TimeoutError: return None, "timeout"
        except Exception as e: return None, str(e)[:80]

    async def _capture_screenshot(self, url: str, market_id: int) -> str:
        """Capture a screenshot of the market URL using Playwright."""
        from playwright.async_api import async_playwright
        from pathlib import Path
        import os
        
        # Ensure URL has http/https prefix
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        # Determine output path
        screenshot_dir = Path("data/screenshots/markets")
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        filename = f"market_{market_id}.png"
        full_path = screenshot_dir / filename
        
        is_onion = ".onion" in url.lower()
        proxy = None
        if is_onion:
            try:
                from utils.tor_manager import ensure_tor_proxy
                tor = await ensure_tor_proxy(settings.TOR_SOCKS_HOST, settings.TOR_SOCKS_PORT)
                if not tor.get("ok"):
                    logger.warning("Skipping onion screenshot; Tor is not verified: %s", tor.get("error"))
                    return ""
                proxy = {"server": tor["proxy_url"]}
            except Exception as tor_err:
                logger.warning("Could not verify Tor in breach screenshot: %s", tor_err)
                return ""
            
        browser = None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    proxy=proxy,
                    args=["--no-sandbox", "--disable-setuid-sandbox"],
                )
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ignore_https_errors=True
                )
                page = await context.new_page()
                
                # Set a reasonable timeout for loading
                timeout = 90000 if is_onion else 60000
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                    # Wait a bit more for dynamic content
                    await asyncio.sleep(3)
                except Exception as e:
                    if "Timeout" in str(e):
                        logger.debug(f"Page load timeout for {url}, proceeding to screenshot anyway")
                    else:
                        raise e
                
                await page.screenshot(path=str(full_path), full_page=False)
                
                # Return path relative to the app root or as served by FastAPI
                return f"/screenshots/markets/{filename}"
        except Exception as e:
            if "Timeout" in str(e):
                logger.warning(f"Screenshot timeout for {url}")
            else:
                logger.warning(f"Screenshot capture failed for {url}: {e}")
            return ""
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
