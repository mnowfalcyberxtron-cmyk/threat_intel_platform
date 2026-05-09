"""
connectors/ransomlook_market.py — Breach Market intelligence from Ransomlook.io
Fetches all tracked market/forum/breach site URLs and persists them to breach_markets.
Runs uptime checks on clearnet URLs via direct HTTP.
"""
import asyncio
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector

logger = logging.getLogger("connector.ransomlook_market")


class RansomlookMarketConnector(BaseConnector):
    name = "ransomlook_market"
    display_name = "RansomLook Breach Market Monitor"
    tier = 1

    # Public endpoints
    GROUPS_URL    = "https://api.ransomlook.io/api/groups"
    CSV_URL       = "https://www.ransomlook.io/urls.csv"
    VICTIMS_URL   = "https://api.ransomlook.io/api/victims/recent"
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
        json_records = await self._fetch_recent_victims_json()
        rss_records  = await self._fetch_recent_victims_rss()
        
        # Deduplicate by victim name and group
        seen = set()
        combined = []
        for r in (json_records + rss_records):
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
            # Try JSON API first
            data = await self._get(self.GROUPS_URL)
            if isinstance(data, list):
                for g in data:
                    name  = (g.get("name") or g.get("group") or "").strip()
                    meta  = g.get("meta") or {}
                    s_type = (meta.get("type") or "group").lower() if isinstance(meta, dict) else "group"
                    desc  = (g.get("description") or "")[:300]
                    for loc in (g.get("locations") or []):
                        raw_url = (loc.get("fqdn") or loc.get("url") or "").strip()
                        if raw_url:
                            url = raw_url if raw_url.startswith("http") else f"https://{raw_url}"
                            markets.append({
                                "name": name, "url": url,
                                "site_type": s_type, "description": desc,
                            })
        except Exception as e:
            logger.warning("RansomLook JSON API failed (%s), trying CSV fallback", e)
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
                                        url = url if url.startswith("http") else f"https://{url}"
                                        markets.append({
                                            "name": name, "url": url,
                                            "site_type": s_type, "description": "",
                                        })
            except Exception as csv_e:
                logger.error("CSV fallback also failed: %s", csv_e)

        if not markets:
            logger.info("No breach market URLs retrieved this cycle")
            return

        logger.info("RansomLook: upserting %d market URLs", len(markets))
        inserted = 0
        updated = 0
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
            except Exception as ue:
                logger.debug("Upsert %s: %s", m["url"], ue)
        
        await db._conn.commit()
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
        """Check live HTTP status of all clearnet breach markets in DB."""
        db = self._get_db()
        if db is None: return
        
        async with db._conn.execute("SELECT id, url, name FROM breach_markets WHERE active=1") as cur:
            rows = await cur.fetchall()

        if not rows: return
        
        logger.info("[RansomLook] Auto-checking uptime for %d breach markets", len(rows))
        semaphore = asyncio.Semaphore(10)
        
        async def _check_one(row):
            async with semaphore:
                status_code, error_msg = await self._check_url_robust(row["url"])
                val = str(status_code) if status_code else f"error:{error_msg[:40]}"
                await db._conn.execute(
                    "UPDATE breach_markets SET last_status=?, last_checked=datetime('now'), updated_at=datetime('now') WHERE id=?",
                    (val, row["id"]),
                )
        
        tasks = [_check_one(r) for r in rows]
        await asyncio.gather(*tasks, return_exceptions=True)
        await db._conn.commit()
        await db.log("INFO", "ransomlook_market", f"Auto-uptime check complete: {len(rows)} markets")

    async def _check_url_robust(self, url: str):
        """Robust HTTP check with HEAD fallback to GET."""
        import aiohttp
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                try:
                    async with sess.head(url, headers=headers, allow_redirects=True, ssl=False) as resp:
                        return resp.status, ""
                except:
                    async with sess.get(url, headers=headers, allow_redirects=True, ssl=False) as resp:
                        return resp.status, ""
        except asyncio.TimeoutError: return None, "timeout"
        except Exception as e: return None, str(e)[:80]

