"""
database/db.py — CyberXTron TIP v2.4 Complete Database Layer
KEY FIX: _migrate() creates ALL missing tables on existing databases.
"""
import json
import logging
import asyncio
import aiosqlite
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import settings
from database.models import ALL_SCHEMAS, DEFAULT_SOURCES

logger = logging.getLogger("database")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self):
        self._db_path = settings.DB_PATH
        self._conn: Optional[aiosqlite.Connection] = None

    async def initialize(self):
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA cache_size=-32000")
        await self._conn.execute("PRAGMA page_size=4096")

        # Apply all schemas - CREATE IF NOT EXISTS is safe on existing DBs
        for schema in ALL_SCHEMAS:
            try:
                await self._conn.execute(schema)
            except Exception as e:
                logger.debug("Schema apply: %s — %s", schema[:60], e)

        await self._conn.commit()
        await self._seed_sources()
        await self._migrate_existing()
        logger.info("Database ready: %s", self._db_path)

    async def _migrate_existing(self):
        """
        Safe migrations for existing databases.
        Adds missing columns without breaking existing data.
        """
        migrations = [
            ("ALTER TABLE ransomware_victims ADD COLUMN source TEXT DEFAULT ''",),
            ("ALTER TABLE ransomware_victims ADD COLUMN source_url TEXT DEFAULT ''",),
            ("ALTER TABLE ransomware_victims ADD COLUMN leak_date TEXT DEFAULT ''",),
            ("ALTER TABLE ransomware_victims ADD COLUMN data_size TEXT DEFAULT ''",),
            ("ALTER TABLE ransomware_victims ADD COLUMN onion_url TEXT DEFAULT ''",),
            ("ALTER TABLE onion_sites ADD COLUMN page_title TEXT DEFAULT ''",),
            ("ALTER TABLE onion_sites ADD COLUMN meta_generator TEXT DEFAULT ''",),
            ("ALTER TABLE onion_sites ADD COLUMN full_html TEXT DEFAULT ''",),
            ("ALTER TABLE onion_sites ADD COLUMN last_content TEXT DEFAULT ''",),
            ("ALTER TABLE onion_sites ADD COLUMN screenshot_path TEXT DEFAULT ''",),
            ("ALTER TABLE onion_sites ADD COLUMN site_type TEXT DEFAULT 'ransomware'",),
            ("UPDATE onion_sites SET screenshot_path = REPLACE(screenshot_path, '\\', '/') WHERE screenshot_path LIKE '%\\%'",),
        ]
        for (sql,) in migrations:
            try:
                await self._conn.execute(sql)
                await self._conn.commit()
            except Exception:
                pass  # Column already exists — that's fine

    async def close(self):
        if self._conn:
            await self._conn.close()

    async def _seed_sources(self):
        for name, display, tier in DEFAULT_SOURCES:
            await self._conn.execute(
                "INSERT OR IGNORE INTO sources (name, display_name, tier, status) VALUES (?,?,?,'pending')",
                (name, display, tier)
            )
        await self._conn.commit()

    # ── IOC Operations ─────────────────────────────────────────────────────────

    async def upsert_ioc(self, record: Dict[str, Any]) -> Tuple[int, bool]:
        ioc   = record.get("ioc", "").strip().lower()
        itype = record.get("ioc_type", "").strip().lower()
        
        # Re-categorize .onion domains as 'onion' to separate from standard clearnet domains
        if ".onion" in ioc and itype == "domain":
            itype = "onion"

        if not ioc or not itype:
            return 0, False
        ts = now_iso()
        async with self._conn.execute(
            "SELECT id, sources, source_count FROM iocs WHERE ioc=? AND ioc_type=?", (ioc, itype)
        ) as cur:
            existing = await cur.fetchone()
        if existing:
            srcs = json.loads(existing["sources"] or "[]")
            src  = record.get("source","unknown")
            if src not in srcs: srcs.append(src)
            conf = self._calc_conf(srcs, record.get("first_seen", ts))
            await self._conn.execute(
                """UPDATE iocs SET sources=?,source_count=?,confidence=?,confidence_label=?,
                   threat_actor=COALESCE(NULLIF(?,''),NULLIF(threat_actor,'unknown'),threat_actor),
                   malware=COALESCE(NULLIF(?,''),malware),tags=?,last_seen=?,updated_at=?
                   WHERE id=?""",
                (json.dumps(srcs), len(srcs), conf, self._clabel(conf),
                 record.get("threat_actor",""), record.get("malware",""),
                 json.dumps(record.get("tags",[])), record.get("last_seen",ts), ts, existing["id"])
            )
            await self._conn.commit()
            return existing["id"], False
        else:
            srcs = [record.get("source","unknown")]
            conf = self._calc_conf(srcs, record.get("first_seen", ts))
            cur  = await self._conn.execute(
                """INSERT INTO iocs (ioc,ioc_type,sources,source_count,threat_actor,malware,
                   malware_family,campaign,tags,confidence,confidence_label,severity,
                   first_seen,last_seen,updated_at,raw_data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ioc, itype, json.dumps(srcs), 1,
                 record.get("threat_actor","unknown"), record.get("malware",""),
                 record.get("malware_family",""), record.get("campaign",""),
                 json.dumps(record.get("tags",[])), conf, self._clabel(conf),
                 record.get("severity","medium"), record.get("first_seen",ts),
                 record.get("last_seen",ts), ts, json.dumps(record.get("raw",{})))
            )
            await self._conn.commit()
            return cur.lastrowid, True

    def _calc_conf(self, sources: list, first_seen: str) -> float:
        w   = settings.SOURCE_WEIGHTS
        base = sum(w.get(s, 0.5) for s in sources) / max(len(sources),1)
        multi = min((len(sources)-1)*0.05, 0.15)
        try:
            ts  = datetime.fromisoformat(first_seen.replace("Z","+00:00"))
            age = (datetime.now(timezone.utc)-ts).total_seconds()/3600
            rec = 0.05 if age<=24 else (0.02 if age<=168 else 0)
        except Exception:
            rec = 0
        return min(round(base+multi+rec, 3), 1.0)

    def _clabel(self, s: float) -> str:
        return "high" if s>=0.75 else "medium" if s>=0.50 else "low"

    async def get_iocs(self, page=1, page_size=50, ioc_type=None, threat_actor=None,
                       malware=None, source=None, confidence=None,
                       date_from=None, date_to=None, search=None) -> Dict:
        where, params = ["ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%')"], []
        if ioc_type:     where.append("ioc_type=?");              params.append(ioc_type)
        if threat_actor: where.append("threat_actor LIKE ?");     params.append(f"%{threat_actor}%")
        if malware:      where.append("malware LIKE ?");          params.append(f"%{malware}%")
        if source:       where.append("sources LIKE ?");          params.append(f"%{source}%")
        if confidence:   where.append("confidence_label=?");      params.append(confidence)
        if date_from:    where.append("last_seen >= ?");          params.append(date_from)
        if date_to:      where.append("last_seen <= ?");          params.append(date_to)
        if search:
            where.append("(ioc LIKE ? OR malware LIKE ? OR threat_actor LIKE ? OR tags LIKE ?)")
            params += [f"%{search}%"]*4
        ws  = ("WHERE "+" AND ".join(where)) if where else ""
        off = (page-1)*page_size
        async with self._conn.execute(f"SELECT COUNT(*) FROM iocs {ws}", params) as cur:
            total = (await cur.fetchone())[0]
        async with self._conn.execute(
            f"SELECT * FROM iocs {ws} ORDER BY confidence DESC,last_seen DESC LIMIT ? OFFSET ?",
            params+[page_size, off]
        ) as cur:
            rows = await cur.fetchall()
        return {"total":total,"page":page,"page_size":page_size,"items":[dict(r) for r in rows]}

    async def get_iocs_for_group(self, threat_actor: str, page_size=300) -> List[Dict]:
        """Get ALL IOC types (including onion/domain) for a specific threat actor group profile."""
        async with self._conn.execute(
            "SELECT * FROM iocs WHERE threat_actor LIKE ? ORDER BY confidence DESC, last_seen DESC LIMIT ?",
            (f"%{threat_actor}%", page_size)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_ioc_by_id(self, ioc_id: int) -> Optional[Dict]:
        async with self._conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_ioc_by_value(self, ioc: str) -> Optional[Dict]:
        async with self._conn.execute("SELECT * FROM iocs WHERE ioc=?", (ioc,)) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    # ── Victim Operations ───────────────────────────────────────────────────────

    async def upsert_victim(self, record: Dict[str, Any]) -> Tuple[int, bool]:
        ts    = now_iso()
        group = (record.get("group_name") or "unknown").strip()
        name  = (record.get("victim_name") or "").strip()
        if not name or len(name) < 2: return 0, False
        
        # Aggressive garbage filtering
        lw_name = name.lower()
        if "://" in lw_name or ".onion" in lw_name or "@" in lw_name: return 0, False
        if any(bad in lw_name for bad in ["news", "alert", "token", "our mirror", "will post", "domain", "index"]): return 0, False
        if lw_name in {"?", "-", "--", "n/a", "na", "unknown", "none", "null"}: return 0, False
        if all(ch in "?-_. " for ch in lw_name): return 0, False
        
        async with self._conn.execute(
            "SELECT id FROM ransomware_victims WHERE LOWER(group_name) = LOWER(?) AND LOWER(victim_name) = LOWER(?)", (group, name)
        ) as cur:
            existing = await cur.fetchone()
        if existing:
            await self._conn.execute(
                """UPDATE ransomware_victims SET
                   description=COALESCE(NULLIF(?,''),description),
                   country=COALESCE(NULLIF(?,''),country),
                   industry=COALESCE(NULLIF(?,''),industry),
                   leak_date=COALESCE(NULLIF(?,''),leak_date),
                   data_size=COALESCE(NULLIF(?,''),data_size),
                   source=COALESCE(NULLIF(?,''),source),
                   source_url=COALESCE(NULLIF(?,''),source_url),
                   onion_url=COALESCE(NULLIF(?,''),onion_url)
                   WHERE id=?""",
                (record.get("description",""), record.get("country",""),
                 record.get("industry",""), record.get("leak_date",""),
                 record.get("data_size",""), record.get("source",""),
                 record.get("source_url",""), record.get("onion_url",""), existing[0])
            )
            await self._conn.commit()
            return existing[0], False
        else:
            cur = await self._conn.execute(
                """INSERT INTO ransomware_victims
                   (group_name,victim_name,description,country,industry,website,
                    leak_date,discovery_date,source,source_url,status,data_size,onion_url)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (group, name, (record.get("description") or "")[:500],
                 (record.get("country") or "").upper(),
                 record.get("industry",""), record.get("website",""),
                 record.get("leak_date",""), record.get("discovery_date",ts),
                 record.get("source",""), record.get("source_url",""),
                 record.get("status","published"), record.get("data_size",""),
                 record.get("onion_url",""))
            )
            await self._conn.commit()
            return cur.lastrowid, True

    async def get_victims(self, page=1, page_size=50, group_name=None,
                          country=None, search=None, date_from=None, source=None) -> Dict:
        where, params = [], []
        if group_name: where.append("v.group_name LIKE ?"); params.append(f"%{group_name}%")
        if country:    where.append("v.country LIKE ?");    params.append(f"%{country}%")
        if source:     where.append("v.source = ?");        params.append(source)
        if search:
            where.append("(v.victim_name LIKE ? OR v.description LIKE ? OR v.group_name LIKE ?)")
            params += [f"%{search}%"]*3
        if date_from:  where.append("v.discovery_date >= ?"); params.append(date_from)
        ws  = ("WHERE "+" AND ".join(where)) if where else ""
        off = (page-1)*page_size
        async with self._conn.execute(f"SELECT COUNT(*) FROM ransomware_victims v {ws}", params) as cur:
            total = (await cur.fetchone())[0]
        async with self._conn.execute(
            f"""SELECT v.*, o.last_status, o.screenshot_path, o.page_title, o.last_checked as monitor_checked
                FROM ransomware_victims v
                LEFT JOIN onion_sites o ON (
                    (v.onion_url <> '' AND v.onion_url = o.url) OR 
                    (v.group_name <> '' AND v.group_name = o.group_name)
                )
                {ws}
                GROUP BY v.id
                ORDER BY v.discovery_date DESC, v.id DESC
                LIMIT ? OFFSET ?""",
            params+[page_size, off]
        ) as cur:
            rows = await cur.fetchall()
        return {"total":total,"page":page,"page_size":page_size,"items":[dict(r) for r in rows]}

    # ── Alert Operations ────────────────────────────────────────────────────────

    async def create_alert(self, alert: Dict) -> int:
        cur = await self._conn.execute(
            """INSERT INTO alerts (alert_type,title,description,severity,ioc_id,victim_id,source,created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (alert.get("alert_type","general"), alert["title"],
             alert.get("description",""), alert.get("severity","medium"),
             alert.get("ioc_id"), alert.get("victim_id"),
             alert.get("source",""), now_iso())
        )
        await self._conn.commit()
        return cur.lastrowid

    async def get_alerts(self, unacknowledged_only=False, alert_type=None, limit=200) -> List[Dict]:
        where = []
        params = []
        if unacknowledged_only: where.append("acknowledged=0")
        if alert_type == "darkweb":
            where.append("alert_type IN ('onion_status_change', 'onion_new_active', 'darkweb_monitor')")
        elif alert_type == "general":
            where.append("alert_type NOT IN ('onion_status_change', 'onion_new_active', 'darkweb_monitor')")
        elif alert_type:
            where.append("alert_type=?")
            params.append(alert_type)
        
        ws = "WHERE " + " AND ".join(where) if where else ""
        async with self._conn.execute(
            f"SELECT * FROM alerts {ws} ORDER BY created_at DESC LIMIT ?", params + [limit]
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def acknowledge_alert(self, alert_id: int):
        await self._conn.execute(
            "UPDATE alerts SET acknowledged=1,acknowledged_at=? WHERE id=?", (now_iso(), alert_id)
        )
        await self._conn.commit()

    # ── Source Status ───────────────────────────────────────────────────────────

    async def update_source_status(self, name: str, status: str, records_fetched=0, error_msg=""):
        ts = now_iso()
        await self._conn.execute(
            """UPDATE sources SET status=?,last_fetched=?,
               last_success=CASE WHEN ?='ok' THEN ? ELSE last_success END,
               records_fetched=?,total_records=total_records+?,error_msg=?
               WHERE name=?""",
            (status,ts,status,ts,records_fetched,records_fetched,error_msg,name)
        )
        await self._conn.commit()

    async def get_sources(self) -> List[Dict]:
        async with self._conn.execute("SELECT * FROM sources ORDER BY tier,name") as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Log Operations ──────────────────────────────────────────────────────────

    async def log(self, level: str, source: str, message: str):
        await self._conn.execute(
            "INSERT INTO logs (timestamp,level,source,message) VALUES (?,?,?,?)",
            (now_iso(), level, source, message)
        )
        await self._conn.commit()

    async def get_logs(self, limit=300, level=None) -> List[Dict]:
        where = "WHERE level=?" if level else ""
        params = [level] if level else []
        async with self._conn.execute(
            f"SELECT * FROM logs {where} ORDER BY timestamp DESC LIMIT ?", params+[limit]
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Stats ────────────────────────────────────────────────────────────────────

    async def get_stats(self) -> Dict:
        # Optimized combined queries to reduce table scans
        (
            ioc_stats, victim_stats, alert_stats, tg_stats,
            top_actors, ioc_types, top_groups, daily, top_malware,
            total_bm
        ) = await asyncio.gather(
            # Combined IOC stats
            self._query_row("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN confidence_label='high' THEN 1 ELSE 0 END) as high_conf,
                    SUM(CASE WHEN updated_at >= datetime('now','-1 day') THEN 1 ELSE 0 END) as new_24h
                FROM iocs 
                WHERE ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%')
            """),
            # Combined Victim stats
            self._query_row("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN discovery_date >= datetime('now','-1 day') THEN 1 ELSE 0 END) as new_24h
                FROM ransomware_victims
            """),
            # Combined Alert stats
            self._query_row("""
                SELECT 
                    SUM(CASE WHEN acknowledged=0 AND alert_type NOT IN ('onion_status_change','onion_new_active','darkweb_monitor') THEN 1 ELSE 0 END) as unack_intel,
                    SUM(CASE WHEN acknowledged=0 AND alert_type IN ('onion_status_change','onion_new_active','darkweb_monitor') THEN 1 ELSE 0 END) as unack_darkweb
                FROM alerts
            """),
            # Combined Telegram stats
            self._query_row("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN last_status='200' THEN 1 ELSE 0 END) as active
                FROM telegram_channels
            """),
            # Heavy aggregations
            self._query_list("SELECT threat_actor,COUNT(*) as cnt FROM iocs WHERE threat_actor NOT IN ('unknown','') GROUP BY threat_actor ORDER BY cnt DESC LIMIT 10"),
            self._query_list("SELECT ioc_type,COUNT(*) as cnt FROM iocs WHERE ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%') GROUP BY ioc_type ORDER BY cnt DESC"),
            self._query_list("SELECT group_name,COUNT(*) as victims FROM ransomware_victims WHERE discovery_date>=datetime('now','-30 days') GROUP BY group_name ORDER BY victims DESC LIMIT 10"),
            self._query_list("SELECT date(updated_at) as day,COUNT(*) as cnt FROM iocs WHERE updated_at>=datetime('now','-7 days') AND ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%') GROUP BY day ORDER BY day"),
            self._query_list("SELECT malware,COUNT(*) as cnt FROM iocs WHERE malware!='' AND confidence_label='high' GROUP BY malware ORDER BY cnt DESC LIMIT 10"),
            # Single count for small table
            self._query_val("SELECT COUNT(*) FROM breach_markets")
        )

        return {
            "total_iocs":            ioc_stats["total"],
            "high_confidence_iocs":  ioc_stats["high_conf"],
            "total_victims":         victim_stats["total"],
            "unacknowledged_alerts_intel":   alert_stats["unack_intel"] or 0,
            "unacknowledged_alerts_darkweb": alert_stats["unack_darkweb"] or 0,
            "new_victims_24h":       victim_stats["new_24h"] or 0,
            "new_iocs_24h":          ioc_stats["new_24h"] or 0,
            "total_telegram":        tg_stats["total"],
            "active_telegram":       tg_stats["active"] or 0,
            "total_breach_markets":  total_bm,
            "top_threat_actors":     top_actors,
            "ioc_type_distribution": ioc_types,
            "top_ransomware_groups": top_groups,
            "daily_ioc_activity":    daily,
            "top_malware":           top_malware,
        }

    async def _query_row(self, sql: str, params: tuple = ()) -> Dict:
        async with self._conn.execute(sql, params) as cur:
            row = await cur.fetchone()
            return dict(row) if row else {}

    async def _query_val(self, sql: str, params: tuple = ()) -> Any:
        async with self._conn.execute(sql, params) as cur:
            row = await cur.fetchone()
            return row[0] if row else None

    async def _query_list(self, sql: str, params: tuple = ()) -> List[Dict]:
        async with self._conn.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ── Reports ──────────────────────────────────────────────────────────────────

    async def save_report(self, report: Dict) -> int:
        cur = await self._conn.execute(
            """INSERT INTO reports (title,summary,threat_actor,malware,targeted_countries,
               targeted_industries,cves,impact,iocs_json,techniques,generated_at,raw_markdown)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (report.get("title",""), report.get("summary",""),
             report.get("threat_actor",""), report.get("malware",""),
             json.dumps(report.get("targeted_countries",[])),
             json.dumps(report.get("targeted_industries",[])),
             json.dumps(report.get("cves",[])), report.get("impact",""),
             json.dumps(report.get("iocs",[])), json.dumps(report.get("techniques",[])),
             now_iso(), report.get("raw_markdown",""))
        )
        await self._conn.commit()
        return cur.lastrowid

    async def get_reports(self, limit=20) -> List[Dict]:
        async with self._conn.execute(
            "SELECT * FROM reports ORDER BY generated_at DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_report_markdown(self, report_id: int) -> Optional[str]:
        async with self._conn.execute("SELECT raw_markdown FROM reports WHERE id=?", (report_id,)) as cur:
            row = await cur.fetchone()
        return row["raw_markdown"] if row else None

    # ── Threat Feed (web intel) ────────────────────────────────────────────────

    async def upsert_feed_item(self, item: Dict) -> Tuple[int, bool]:
        url = item.get("url","").strip()
        if not url: return 0, False
        async with self._conn.execute("SELECT id FROM threat_feed WHERE url=?", (url,)) as cur:
            existing = await cur.fetchone()
        if existing: return existing["id"], False
        try:
            cur = await self._conn.execute(
                """INSERT INTO threat_feed (title,summary,url,source,source_type,category,
                   entities,published,fetched_at,relevance) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (item.get("title","")[:200], item.get("summary","")[:500], url,
                 item.get("source",""), item.get("source_type","web"),
                 item.get("category","general"), json.dumps(item.get("entities",[])),
                 item.get("published",now_iso()), item.get("fetched_at",now_iso()),
                 item.get("relevance",0.5))
            )
            await self._conn.commit()
            return cur.lastrowid, True
        except Exception as e:
            if "UNIQUE" in str(e): return 0, False
            raise

    async def get_feed(self, limit=50, category=None, hours=24, min_relevance=0.3) -> List[Dict]:
        """
        Fetch latest feed items. 
        Filters by 'published' date if possible to avoid showing old items in 'Last 24 Hours'.
        """
        # We filter by published date to respect the actual news age, 
        # but also allow recently fetched items if published is missing or in the future
        where = [
            f"(published >= datetime('now','-{hours} hours') OR fetched_at >= datetime('now','-{hours} hours'))",
            "relevance >= ?"
        ]
        params: List[Any] = [min_relevance]
        if category: where.append("category=?"); params.append(category)
        ws = "WHERE "+" AND ".join(where)
        
        # Sort by published DESC first, so 2025 news ends up at the bottom even if fetched today
        async with self._conn.execute(
            f"SELECT * FROM threat_feed {ws} ORDER BY published DESC, fetched_at DESC LIMIT ?",
            params+[limit]
        ) as cur:
            rows = await cur.fetchall()
        items = []
        for r in rows:
            d = dict(r)
            try: d["entities"] = json.loads(d.get("entities","[]"))
            except: d["entities"] = []
            items.append(d)
        return items

    async def search_feed(self, query: str, limit=20) -> List[Dict]:
        q = f"%{query}%"
        async with self._conn.execute(
            "SELECT * FROM threat_feed WHERE title LIKE ? OR summary LIKE ? OR entities LIKE ? ORDER BY relevance DESC,fetched_at DESC LIMIT ?",
            (q,q,q,limit)
        ) as cur:
            rows = await cur.fetchall()
        items = []
        for r in rows:
            d = dict(r)
            try: d["entities"] = json.loads(d.get("entities","[]"))
            except: d["entities"] = []
            items.append(d)
        return items

    async def get_feed_context_for_ai(self, topic: str, limit=8) -> str:
        items = await self.search_feed(topic, limit=limit)
        if not items: items = await self.get_feed(limit=limit, min_relevance=0.5)
        if not items: return ""
        lines = ["## Recent Intelligence from Live Web Feed (verified sources)\n"]
        for i, item in enumerate(items[:6], 1):
            pub = (item.get("published") or "")[:10]
            ents = ", ".join(item.get("entities",[])[:4])
            lines.append(
                f"**[{i}] {item['title']}**\n"
                f"Source: {item['source']} | Date: {pub}\n"
                f"Tags: {ents or 'general'}\n"
                f"{item.get('summary','')[:200]}\n"
                f"URL: {item.get('url','')}\n"
            )
        return "\n".join(lines)

    async def clean_old_feed(self, hours=72):
        await self._conn.execute(
            "DELETE FROM threat_feed WHERE fetched_at<datetime('now',?)", (f"-{hours} hours",)
        )
        await self._conn.commit()

    # ── Advisories ────────────────────────────────────────────────────────────

    async def upsert_advisory(self, item: Dict) -> Tuple[int, bool]:
        url = item.get("url","").strip()
        if not url: return 0, False
        async with self._conn.execute("SELECT id FROM advisories WHERE url=?", (url,)) as cur:
            existing = await cur.fetchone()
        
        if existing:
            # Update existing record to fix previously broken dates
            await self._conn.execute(
                "UPDATE advisories SET published=?, title=?, summary=?, fetched_at=? WHERE id=?",
                (item.get("published",""), item.get("title","")[:200], item.get("summary","")[:600], now_iso(), existing["id"])
            )
            await self._conn.commit()
            return existing["id"], False
            
        try:
            cur = await self._conn.execute(
                """INSERT INTO advisories (company,advisory_type,source_name,title,summary,url,
                   published,fetched_at,cves,iocs,mitre_ttps,severity,category)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (item.get("company","General"), item.get("advisory_type","official"),
                 item.get("source_name",""), item.get("title","")[:200],
                 item.get("summary","")[:600], url,
                 item.get("published",""), item.get("fetched_at",now_iso()),
                 json.dumps(item.get("cves",[])), json.dumps(item.get("iocs",{})),
                 json.dumps(item.get("mitre_ttps",[])), item.get("severity","medium"),
                 item.get("category","advisory"))
            )
            await self._conn.commit()
            return cur.lastrowid, True
        except Exception as e:
            if "UNIQUE" in str(e): return 0, False
            raise

    async def get_advisories(self, page=1, page_size=50, company=None, severity=None,
                              category=None, advisory_type=None, search=None, hours=168) -> Dict:
        """
        Fetch advisories. 
        CRITICAL: Filter by PUBLISHED date to avoid showing old (e.g. 2025) news that was just fetched.
        """
        # If hours=0 (all time), we don't filter.
        where = []
        if hours > 0:
            # Use published date primarily to exclude old news, fallback to fetched_at if published is missing
            where.append(f"(CASE WHEN published IS NULL OR published='' THEN fetched_at ELSE published END) >= datetime('now','-{hours} hours')")
        
        params: List[Any] = []
        if company:       where.append("company LIKE ?");      params.append(f"%{company}%")
        if severity:      where.append("severity=?");          params.append(severity)
        if category:      where.append("category=?");          params.append(category)
        if advisory_type: where.append("advisory_type=?");     params.append(advisory_type)
        if search:
            where.append("(title LIKE ? OR summary LIKE ? OR company LIKE ?)")
            params += [f"%{search}%"]*3
        ws  = "WHERE "+" AND ".join(where)
        off = (page-1)*page_size
        async with self._conn.execute(f"SELECT COUNT(*) FROM advisories {ws}", params) as cur:
            total = (await cur.fetchone())[0]
        async with self._conn.execute(
            f"SELECT * FROM advisories {ws} ORDER BY published DESC, fetched_at DESC LIMIT ? OFFSET ?",
            params+[page_size, off]
        ) as cur:
            rows = await cur.fetchall()
        items = []
        for r in rows:
            d = dict(r)
            for f in ("cves","iocs","mitre_ttps"):
                try: d[f] = json.loads(d.get(f) or ("[]" if f!="iocs" else "{}"))
                except: d[f] = {} if f=="iocs" else []
            items.append(d)
        return {"total":total,"page":page,"page_size":page_size,"items":items}

    async def sync_discovered_onions(self):
        """Automatically add discovered .onion sites to the onion_sites table."""
        try:
            discovered = await self.get_discovered_onion_sites()
            for s in discovered:
                url = s["url"].lower()
                # Use INSERT OR IGNORE to avoid duplicates
                await self._conn.execute(
                    """INSERT OR IGNORE INTO onion_sites 
                       (group_name, url, description, active, created_at, last_checked, last_status) 
                       VALUES (?, ?, ?, 1, datetime('now'), NULL, 'pending')""",
                    (s["group_name"], s["url"], "Discovered automatically from intelligence feeds")
                )
            await self._conn.commit()
        except Exception as e:
            import logging
            logging.getLogger("db").error(f"sync_discovered_onions failed: {e}")

    async def get_advisory_stats(self) -> Dict:
        async with self._conn.execute(
            "SELECT company,COUNT(*) as cnt FROM advisories GROUP BY company ORDER BY cnt DESC LIMIT 10"
        ) as cur: top = [dict(r) for r in await cur.fetchall()]
        async with self._conn.execute(
            "SELECT severity,COUNT(*) as cnt FROM advisories GROUP BY severity"
        ) as cur: sev = [dict(r) for r in await cur.fetchall()]
        async with self._conn.execute(
            "SELECT COUNT(*) FROM advisories WHERE fetched_at>=datetime('now','-1 day')"
        ) as cur: today = (await cur.fetchone())[0]
        async with self._conn.execute(
            "SELECT COUNT(*) FROM advisories WHERE severity='critical'"
        ) as cur: crit = (await cur.fetchone())[0]
        return {"top_companies":top,"by_severity":sev,"today":today,"critical_total":crit}

    async def get_advisory_context_for_ai(self, company: str, limit=5) -> str:
        data = await self.get_advisories(company=company, page_size=limit, hours=168)
        items = data.get("items",[])
        if not items: return ""
        lines = [f"## Recent Security Advisories for {company} (from monitored feeds)\n"]
        for i, a in enumerate(items, 1):
            cves = a.get("cves",[])
            lines.append(
                f"**[{i}] [{a['severity'].upper()}] {a['title']}**\n"
                f"Source: {a['source_name']} ({a['advisory_type']}) | Date: {a.get('published','?')[:10]}\n"
                f"CVEs: {', '.join(cves[:5]) if cves else 'none'}\n"
                f"Summary: {a.get('summary','')[:200]}\n"
                f"URL: {a.get('url','')}\n"
            )
        return "\n".join(lines)

    async def get_discovered_onion_sites(self) -> List[Dict]:
        """
        Extract unique .onion URLs from the ransomware_victims and iocs tables.
        Cross-references group names to find missing onion links for known actors.
        """
        # 1. Direct discovery from victims
        async with self._conn.execute(
            """SELECT DISTINCT group_name, 
               CASE WHEN onion_url LIKE '%.onion%' THEN onion_url ELSE source_url END as url
               FROM ransomware_victims 
               WHERE source_url LIKE '%.onion%' OR onion_url LIKE '%.onion%'"""
        ) as cur:
            v_rows = await cur.fetchall()
        
        # 2. Direct discovery from IOCs
        async with self._conn.execute(
            """SELECT DISTINCT threat_actor as group_name, ioc as url
               FROM iocs 
               WHERE ioc_type IN ('domain', 'onion') AND ioc LIKE '%.onion%'"""
        ) as cur:
            i_rows = await cur.fetchall()

        # 3. Indirect discovery
        async with self._conn.execute(
            """SELECT DISTINCT v.group_name, i.ioc as url
               FROM ransomware_victims v
               JOIN iocs i ON LOWER(v.group_name) = LOWER(i.threat_actor)
               WHERE i.ioc_type IN ('domain', 'onion') AND i.ioc LIKE '%.onion%'"""
        ) as cur:
            iv_rows = await cur.fetchall()

        results = []
        seen_urls = {s["url"].lower() for s in await self.get_all_onion_sites(active_only=False)}
        
        for row in v_rows + i_rows + iv_rows:
            g = (row["group_name"] or "unknown").strip()
            u = (row["url"] or "").strip().lower()
            if g and u and ".onion" in u:
                if u not in seen_urls:
                    results.append({"group_name": g, "url": u, "last_status": "pending"})
                    seen_urls.add(u)
        return results

    async def get_onion_for_group(self, group_name: str) -> Optional[str]:
        """Try to find a .onion URL for a given group name."""
        # Check victims first
        async with self._conn.execute(
            "SELECT onion_url FROM ransomware_victims WHERE LOWER(group_name)=? AND onion_url LIKE '%.onion%' LIMIT 1",
            (group_name.lower(),)
        ) as cur:
            row = await cur.fetchone()
            if row: return row[0]
            
        # Check IOCs
        async with self._conn.execute(
            "SELECT ioc FROM iocs WHERE LOWER(threat_actor)=? AND ioc LIKE '%.onion%' LIMIT 1",
            (group_name.lower(),)
        ) as cur:
            row = await cur.fetchone()
            if row: return row[0]
        return None

    async def sync_discovered_onions(self):
        """
        Extract .onion links from ransomware_victims and add them 
        to the onion_sites table for automated monitoring.
        """
        logger.info("[DB] Syncing discovered onion sites from ransomware victims...")
        discovered = await self.get_discovered_onion_sites()
        new_count = 0
        for site in discovered:
            try:
                # Use INSERT OR IGNORE and then check rowcount 
                # (though with aiosqlite sometimes rowcount is tricky after insert or ignore)
                async with self._conn.execute(
                    "INSERT OR IGNORE INTO onion_sites (group_name, url) VALUES (?, ?)",
                    (site["group_name"], site["url"])
                ) as cur:
                    if cur.rowcount > 0:
                        new_count += 1
            except Exception:
                pass
        await self._conn.commit()
        if new_count > 0:
            logger.info(f"[DB] Discovered {new_count} new unique .onion links.")
        return new_count

    async def get_all_onion_sites(self, active_only=True) -> List[Dict]:
        where = "WHERE active=1" if active_only else ""
        async with self._conn.execute(f"SELECT * FROM onion_sites {where}") as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def update_onion_scrape(self, site_id: int, title: str, generator: str, 
                                 content: str, full_html: str, screenshot_path: str):
        now = now_iso()
        await self._conn.execute(
            """UPDATE onion_sites SET 
               page_title=?, meta_generator=?, last_content=?, full_html=?, 
               screenshot_path=?, last_checked=?, last_status='200' 
               WHERE id=?""",
            (title, generator, content, full_html, screenshot_path, now, site_id)
        )
        await self._conn.commit()

    # ── Social Intelligence ───────────────────────────────────────────────────

    async def upsert_social_intel(self, item: Dict) -> Tuple[int, bool]:
        url = item.get("source_url", "").strip()
        if not url: return 0, False
        async with self._conn.execute("SELECT id FROM social_intel WHERE source_url=?", (url,)) as cur:
            existing = await cur.fetchone()
        if existing: return existing["id"], False
        
        try:
            cur = await self._conn.execute(
                """INSERT INTO social_intel (platform,source_url,content,author,threat_type,
                   published,fetched_at,entities,raw_json) VALUES (?,?,?,?,?,?,?,?,?)""",
                (item.get("platform", "X"), url, item.get("content", ""),
                 item.get("author", ""), item.get("threat_type", "emerging"),
                 item.get("published", now_iso()), item.get("fetched_at", now_iso()),
                 json.dumps(item.get("entities", [])), json.dumps(item.get("raw", {})))
            )
            await self._conn.commit()
            return cur.lastrowid, True
        except Exception as e:
            if "UNIQUE" in str(e): return 0, False
            raise

    async def get_social_intel(self, page=1, page_size=50, platform=None, threat_type=None) -> Dict:
        where, params = [], []
        if platform:    where.append("platform=?");    params.append(platform)
        if threat_type: where.append("threat_type=?"); params.append(threat_type)
        ws  = ("WHERE "+" AND ".join(where)) if where else ""
        off = (page-1)*page_size
        async with self._conn.execute(f"SELECT COUNT(*) FROM social_intel {ws}", params) as cur:
            total = (await cur.fetchone())[0]
        async with self._conn.execute(
            f"SELECT * FROM social_intel {ws} ORDER BY published DESC LIMIT ? OFFSET ?",
            params+[page_size, off]
        ) as cur:
            rows = await cur.fetchall()
        items = []
        for r in rows:
            d = dict(r)
            try: d["entities"] = json.loads(d.get("entities", "[]"))
            except: d["entities"] = []
            items.append(d)
        return {"total": total, "page": page, "page_size": page_size, "items": items}

    # ── Telegram Operations ───────────────────────────────────────────────────

    async def upsert_telegram_channel(self, item: Dict) -> Tuple[int, bool]:
        handle = item.get("handle", "").strip().lower()
        if not handle: return 0, False
        url = f"https://t.me/{handle}"
        
        async with self._conn.execute("SELECT id FROM telegram_channels WHERE handle=?", (handle,)) as cur:
            existing = await cur.fetchone()
        
        if existing:
            await self._conn.execute(
                """UPDATE telegram_channels SET
                   name=COALESCE(NULLIF(?,''), name),
                   description=COALESCE(NULLIF(?,''), description),
                   category=COALESCE(NULLIF(?,''), category),
                   subscriber_count=CASE WHEN ?>0 THEN ? ELSE subscriber_count END,
                   updated_at=datetime('now')
                   WHERE id=?""",
                (item.get("name", ""), item.get("description", ""),
                 item.get("category", "general"), item.get("subscriber_count", 0),
                 item.get("subscriber_count", 0), existing[0])
            )
            await self._conn.commit()
            return existing[0], False
        else:
            cur = await self._conn.execute(
                """INSERT INTO telegram_channels (name, handle, url, description, category, subscriber_count)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (item.get("name") or handle, handle, url, item.get("description", ""),
                 item.get("category", "general"), item.get("subscriber_count", 0))
            )
            await self._conn.commit()
            return cur.lastrowid, True

    async def get_telegram_channels(self, page=1, page_size=50, category=None, status=None, search=None) -> Dict:
        where, params = [], []
        if category: where.append("category=?"); params.append(category)
        if status:   where.append("last_status=?"); params.append(status)
        if search:
            where.append("(name LIKE ? OR handle LIKE ? OR description LIKE ?)")
            params += [f"%{search}%"]*3
        
        ws = ("WHERE "+" AND ".join(where)) if where else ""
        off = (page-1)*page_size
        async with self._conn.execute(f"SELECT COUNT(*) FROM telegram_channels {ws}", params) as cur:
            total = (await cur.fetchone())[0]
        
        async with self._conn.execute(
            f"SELECT * FROM telegram_channels {ws} ORDER BY subscriber_count DESC, updated_at DESC LIMIT ? OFFSET ?",
            params+[page_size, off]
        ) as cur:
            rows = await cur.fetchall()
        
        return {"total": total, "page": page, "page_size": page_size, "items": [dict(r) for r in rows]}

    async def update_telegram_status(self, channel_id: int, status: str, sub_count: int = 0):
        await self._conn.execute(
            "UPDATE telegram_channels SET last_status=?, subscriber_count=?, last_checked=datetime('now'), updated_at=datetime('now') WHERE id=?",
            (status, sub_count, channel_id)
        )
        await self._conn.commit()

    # ── User Auth ────────────────────────────────────────────────────────────

    async def create_user(self, name: str, email: str, password_hash: str, role: str = "user") -> int:
        cur = await self._conn.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            (name, email.lower(), password_hash, role)
        )
        await self._conn.commit()
        return cur.lastrowid

    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        async with self._conn.execute("SELECT * FROM users WHERE email=?", (email.lower(),)) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_all_users(self) -> List[Dict]:
        async with self._conn.execute("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC") as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def delete_user(self, user_id: int) -> bool:
        cur = await self._conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        await self._conn.commit()
        return cur.rowcount > 0

    async def log_user_activity(self, user_id: int, action: str, details: str = "", ip: str = ""):
        try:
            await self._conn.execute(
                "INSERT INTO user_activity (user_id, action, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, details, ip, now_iso())
            )
            await self._conn.commit()
        except Exception:
            # Skip logging if user doesn't exist (common after DB reset)
            pass

    async def get_user_activity(self, user_id: int, limit: int = 50) -> List[Dict]:
        async with self._conn.execute(
            "SELECT * FROM user_activity WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
            (user_id, limit)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]
