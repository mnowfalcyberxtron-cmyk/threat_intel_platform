"""
database/db.py — ThreatIntel TIP v2.4 Complete Database Layer
KEY FIX: _migrate() creates ALL missing tables on existing databases.
"""
import json
import logging
import asyncio
import asyncpg
import urllib.parse

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import settings
from database.models import ALL_SCHEMAS, DEFAULT_SOURCES

logger = logging.getLogger("database")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_PLACEHOLDER_VALUES = {"", "unknown", "n/a", "na", "none", "null", "-", "see advisory", "see vendor advisory"}


def _is_placeholder_text(value: Any) -> bool:
    return str(value or "").strip().lower() in _PLACEHOLDER_VALUES


def _derive_fixed_version_hint(text: Any) -> str:
    """Best-effort extraction of a fixed version from affected-version text."""
    raw = str(text or "").strip()
    if not raw or _is_placeholder_text(raw):
        return "Unknown"

    patterns = [
        r"(?i)(?:fixed in|patched in|resolved in|update to|upgrade to|upgrade to version|update to version|available in)\s*(?:version\s*)?([A-Za-z0-9][A-Za-z0-9_.\-+/:]*)",
        r"(?i)(?:version|v)\s*([0-9][A-Za-z0-9_.\-+/:]*)\s*(?:and later|or later|or newer|and newer)",
        r"(?i)(?:prior to|before|less than|earlier than|older than|under)\s*(?:v(?:ersion)?\s*)?([A-Za-z0-9][A-Za-z0-9_.\-+/:]*)",
        r"(?i)(?:<|<=)\s*v?([A-Za-z0-9][A-Za-z0-9_.\-+/:]*)",
    ]

    for pattern in patterns:
        match = re.search(pattern, raw)
        if not match:
            continue
        value = (match.group(1) if match.groups() else match.group(0)).strip()
        value = value.lstrip("vV").strip()
        if not value or value.lower() in {"all/*", "all"}:
            continue
        if any(ch.isdigit() for ch in value) or re.search(r"[A-Za-z].*\d|\d.*[A-Za-z]", value):
            return value[:80]

    return "Unknown"



class CursorWrapper:
    def __init__(self, conn, sql, params):
        self.conn = conn
        self.sql = sql
        self.params = params
        self._fetched = None
        self._rowcount = 0
        self._lastrowid = 0

    def __await__(self):
        return self._execute().__await__()

    async def __aenter__(self):
        await self._execute()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def _execute(self):
        parts = self.sql.split('?')
        pg_sql = parts[0] + ''.join(f'${i+1}{p}' for i, p in enumerate(parts[1:]))
        
        pg_sql = pg_sql.replace('INSERT OR IGNORE INTO', 'INSERT INTO')
        pg_sql = pg_sql.replace("datetime('now')", "NOW()")
        pg_sql = pg_sql.replace("datetime('now','-1 day')", "NOW() - INTERVAL '1 day'")
        pg_sql = pg_sql.replace("datetime('now','-7 days')", "NOW() - INTERVAL '7 days'")
        pg_sql = pg_sql.replace("datetime('now','-30 days')", "NOW() - INTERVAL '30 days'")
        pg_sql = pg_sql.replace("datetime('now','start of day')", "CURRENT_DATE::timestamp")
        
        if pg_sql.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
            if pg_sql.strip().upper().startswith("INSERT") and "RETURNING" not in pg_sql.upper() and "ON CONFLICT" not in pg_sql.upper():
                try:
                    record = await self.conn.fetchrow(pg_sql + " RETURNING id", *self.params)
                    self._lastrowid = record['id'] if record and 'id' in record else 0
                    self._rowcount = 1
                    return self
                except asyncpg.exceptions.UndefinedColumnError:
                    pass
            
            res = await self.conn.execute(pg_sql, *self.params)
            try:
                self._rowcount = int(res.split()[-1])
            except:
                self._rowcount = 1
        else:
            self._fetched = await self.conn.fetch(pg_sql, *self.params)
        return self

    async def fetchall(self):
        if self._fetched is None:
            await self._execute()
        if not self._fetched: return []
        return [dict(r) for r in self._fetched]

    async def fetchone(self):
        if self._fetched is None:
            await self._execute()
        if not self._fetched:
            return None
        return dict(self._fetched[0])

    @property
    def lastrowid(self):
        return self._lastrowid

    @property
    def rowcount(self):
        return self._rowcount

class ConnectionWrapper:
    def __init__(self, pg_conn):
        self.pg_conn = pg_conn

    def execute(self, sql, params=()):
        return CursorWrapper(self.pg_conn, sql, params)
        
    async def commit(self):
        pass

    async def close(self):
        await self.pg_conn.close()


class Database:
    def __init__(self):
        self._db_url = (
            getattr(settings, "DATABASE_URL", "")
            or getattr(settings, "POSTGRES_URL", "")
        )
        self._db_path = settings.DB_PATH
        self._conn = None

    async def initialize(self):
        db_url = (
            getattr(settings, "DATABASE_URL", "")
            or getattr(settings, "POSTGRES_URL", "")
        )
        if not db_url:
            db_url = "postgresql://postgres:postgres@localhost:5432/threatintel"
            
        pg_conn = await asyncpg.connect(db_url)
        self._conn = ConnectionWrapper(pg_conn)

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
            ("ALTER TABLE ics_advisories ADD COLUMN vendor_hq TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN product_distribution TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN kev_flag TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN nist_url TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN csaf_url TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN release_year INTEGER DEFAULT NULL",),
            ("ALTER TABLE ics_advisories ADD COLUMN release_month INTEGER DEFAULT NULL",),
            ("ALTER TABLE ics_advisories ADD COLUMN update_year INTEGER DEFAULT NULL",),
            ("ALTER TABLE ics_advisories ADD COLUMN update_month INTEGER DEFAULT NULL",),
            ("ALTER TABLE ics_advisories ADD COLUMN cve_year INTEGER DEFAULT NULL",),
            ("ALTER TABLE ics_advisories ADD COLUMN nvd_cvss_v4_score TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN nvd_enrichment_status TEXT DEFAULT 'pending'",),
            # CVEList V5 enrichment columns (cve_published_date from GitHub cvelistV5 zip)
            ("ALTER TABLE ics_advisories ADD COLUMN cve_published_date TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN cve_updated_date TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN cve_pub_year INTEGER DEFAULT NULL",),
            ("ALTER TABLE ics_advisories ADD COLUMN cve_pub_month INTEGER DEFAULT NULL",),
            ("ALTER TABLE ics_advisories ADD COLUMN cvelist_status TEXT DEFAULT 'pending'",),
            # AI enrichment columns
            ("ALTER TABLE ics_advisories ADD COLUMN ai_enriched INTEGER DEFAULT 0",),
            ("ALTER TABLE ics_advisories ADD COLUMN patch_available_bool TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN poc_available_bool TEXT DEFAULT ''",),
            ("ALTER TABLE ics_advisories ADD COLUMN xtron_score INTEGER DEFAULT NULL",),
        ]
        for (sql,) in migrations:
            try:
                await self._conn.execute(sql)
                await self._conn.commit()
            except Exception:
                pass  # Column already exists — that's fine

        try:
            await self._conn.execute(
                """UPDATE ics_advisories
                   SET
                     release_year = COALESCE(release_year, CAST(
                       CASE
                         WHEN substr(trim(release_date), 5, 1) = '-' THEN substr(trim(release_date), 1, 4)
                         WHEN instr(trim(release_date), '/') > 0 THEN substr(trim(release_date), length(trim(release_date))-3, 4)
                         WHEN lower(substr(trim(release_date), 1, 3)) IN ('jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec')
                           THEN substr(trim(release_date), length(trim(release_date))-3, 4)
                         ELSE NULL
                       END AS INTEGER)),
                     release_month = COALESCE(release_month, CAST(
                       CASE
                         WHEN substr(trim(release_date), 5, 1) = '-' THEN substr(trim(release_date), 6, 2)
                         WHEN instr(trim(release_date), '/') > 0 THEN substr(trim(release_date), 1, instr(trim(release_date), '/')-1)
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'jan' THEN '1'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'feb' THEN '2'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'mar' THEN '3'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'apr' THEN '4'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'may' THEN '5'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'jun' THEN '6'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'jul' THEN '7'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'aug' THEN '8'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'sep' THEN '9'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'oct' THEN '10'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'nov' THEN '11'
                         WHEN lower(substr(trim(release_date), 1, 3)) = 'dec' THEN '12'
                         ELSE NULL
                       END AS INTEGER)),
                     cve_year = COALESCE(cve_year, CAST(
                       CASE WHEN upper(cve_id) LIKE 'CVE-____-%' THEN substr(cve_id, 5, 4) ELSE NULL END
                       AS INTEGER))
                   WHERE release_year IS NULL OR release_month IS NULL OR cve_year IS NULL"""
            )
            await self._conn.commit()
        except Exception as exc:
            logger.debug("ICS date-part backfill skipped: %s", exc)

        for sql in (
            "CREATE INDEX IF NOT EXISTS idx_ics_release_ym ON ics_advisories(release_year, release_month)",
            "CREATE INDEX IF NOT EXISTS idx_ics_cve_year ON ics_advisories(cve_year)",
            "CREATE INDEX IF NOT EXISTS idx_ics_cve_pub_ym ON ics_advisories(cve_pub_year, cve_pub_month)",
        ):
            try:
                await self._conn.execute(sql)
                await self._conn.commit()
            except Exception:
                pass

    async def close(self):
        if self._conn:
            await self._conn.close()

    async def _retry_execute(self, sql: str, params=None, max_retries=3, delay=0.1):
        """Execute with automatic retry on database lock."""
        for attempt in range(max_retries):
            try:
                return await self._conn.execute(sql, params or ())
            except asyncpg.exceptions.PostgresError as e:
                if "database is locked" not in str(e):
                    raise
                if attempt == max_retries - 1:
                    raise
                wait_time = delay * (2 ** attempt)  # exponential backoff
                await asyncio.sleep(wait_time)
        
    async def _retry_commit(self, max_retries=3, delay=0.1):
        """Commit with automatic retry on database lock."""
        for attempt in range(max_retries):
            try:
                return await self._conn.commit()
            except asyncpg.exceptions.PostgresError as e:
                if "database is locked" not in str(e):
                    raise
                if attempt == max_retries - 1:
                    raise
                wait_time = delay * (2 ** attempt)
                await asyncio.sleep(wait_time)

    async def _seed_sources(self):
        for name, display, tier in DEFAULT_SOURCES:
            await self._conn.execute(
                "INSERT OR IGNORE INTO sources (name, display_name, tier, status) VALUES (?,?,?,'pending')",
                (name, display, tier)
            )
        await self._conn.commit()

    # ── IOC Operations ─────────────────────────────────────────────────────────

    async def upsert_ioc(self, record: dict) -> tuple[int, bool]:
        ioc   = record.get("ioc", "").strip().lower()
        itype = record.get("ioc_type", "").strip().lower()
        
        # Re-categorize .onion domains as 'onion' to separate from standard clearnet domains
        if ".onion" in ioc and itype == "domain":
            itype = "onion"

        if not ioc or not itype:
            return 0, False
        
        # ensure ts is available
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        
        async with self._conn.execute(
            "SELECT id, sources, source_count FROM iocs WHERE ioc=? AND ioc_type=?", (ioc, itype)
        ) as cur:
            existing = await cur.fetchone()
        if existing:
            import json
            srcs = json.loads(existing["sources"] or "[]")
            src  = record.get("source","unknown")
            if src not in srcs: srcs.append(src)
            conf = self._calc_conf(srcs, record.get("first_seen", ts))
            await self._conn.execute(
                """UPDATE iocs SET sources=?,source_count=?,confidence=?,confidence_label=?,
                   threat_actor=COALESCE(NULLIF(?,''),NULLIF(threat_actor,'unknown'),threat_actor),
                   malware=COALESCE(NULLIF(?,''),malware),campaign=COALESCE(NULLIF(?,''),campaign),
                   tags=?,last_seen=?,updated_at=?
                   WHERE id=?""",
                (json.dumps(srcs), len(srcs), conf, self._clabel(conf),
                 record.get("threat_actor",""), record.get("malware",""),
                 record.get("campaign",""),
                 json.dumps(record.get("tags",[])), record.get("last_seen",ts), ts, existing["id"])
            )
            await self._conn.commit()
            return existing["id"], False
        else:
            import json
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
            from datetime import datetime, timezone
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

    async def get_campaigns(self, limit=50) -> List[Dict]:
        async with self._conn.execute(
            "SELECT campaign, COUNT(*) as ioc_count, MAX(last_seen) as last_seen FROM iocs WHERE campaign != '' GROUP BY campaign ORDER BY last_seen DESC LIMIT ?",
            (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_campaign_iocs(self, campaign: str, limit=200) -> List[Dict]:
        async with self._conn.execute(
            "SELECT * FROM iocs WHERE campaign = ? ORDER BY last_seen DESC LIMIT ?",
            (campaign, limit)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_actor_links(self, actor: str) -> List[Dict]:
        links = []
        # Get onion sites
        async with self._conn.execute(
            "SELECT url, 'onion' as type FROM onion_sites WHERE group_name = ? AND active = 1",
            (actor,)
        ) as cur:
            onion_rows = await cur.fetchall()
            for r in onion_rows:
                links.append({"url": r["url"], "type": "onion"})
        
        # Get telegram channels matching name loosely
        like_actor = f"%{actor}%"
        async with self._conn.execute(
            "SELECT url, 'telegram' as type FROM telegram_channels WHERE name LIKE ? OR handle LIKE ?",
            (like_actor, like_actor)
        ) as cur:
            tg_rows = await cur.fetchall()
            for r in tg_rows:
                links.append({"url": r["url"], "type": "telegram"})
                
        return links

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
        try:
            await self._retry_execute(
                """UPDATE sources SET status=?,last_fetched=?,
                   last_success=CASE WHEN ?='ok' THEN ? ELSE last_success END,
                   records_fetched=?,total_records=total_records+?,error_msg=?
                   WHERE name=?""",
                (status, ts, status, ts, records_fetched, records_fetched, error_msg, name),
                max_retries=5
            )
            await self._retry_commit(max_retries=5)
        except Exception as e:
            logger.warning(f"Failed to update source status for {name}: {e}")

    async def get_sources(self) -> List[Dict]:
        async with self._conn.execute("SELECT * FROM sources ORDER BY tier,name") as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Log Operations ──────────────────────────────────────────────────────────

    async def log(self, level: str, source: str, message: str):
        try:
            await self._retry_execute(
                "INSERT INTO logs (timestamp,level,source,message) VALUES (?,?,?,?)",
                (now_iso(), level, source, message),
                max_retries=3
            )
            await self._retry_commit(max_retries=3)
        except Exception as e:
            logger.debug(f"Failed to log message: {e}")

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
            total_bm, total_onion, total_adv, total_ics
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
            self._query_val("SELECT COUNT(*) FROM breach_markets"),
            self._query_val("SELECT COUNT(*) FROM onion_sites"),
            self._query_val("SELECT COUNT(*) FROM advisories"),
            self._query_val("SELECT COUNT(*) FROM ics_advisories")
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
            "total_onion_sites":     total_onion,
            "total_advisories":      total_adv,
            "total_ics_advisories":  total_ics,
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
        if str(hours) == "today":
            time_filter = "(published >= datetime('now','start of day') OR fetched_at >= datetime('now','start of day'))"
        else:
            time_filter = f"(published >= datetime('now','-{hours} hours') OR fetched_at >= datetime('now','-{hours} hours'))"
        where = [
            time_filter,
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
            except Exception: d["entities"] = []
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
            except Exception: d["entities"] = []
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
        # Prune status_history older than 30 days (720 hours) to prevent bloat
        await self._conn.execute(
            "DELETE FROM status_history WHERE timestamp<datetime('now','-30 days')"
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
        # If hours="today", we filter since midnight (start of day). Otherwise check numeric hours.
        where = []
        if str(hours) == "today":
            where.append("(CASE WHEN published IS NULL OR published='' THEN fetched_at ELSE published END) >= datetime('now','start of day')")
        else:
            try:
                h_int = int(hours)
            except ValueError:
                h_int = 168
            if h_int > 0:
                # Use published date primarily to exclude old news, fallback to fetched_at if published is missing
                where.append(f"(CASE WHEN published IS NULL OR published='' THEN fetched_at ELSE published END) >= datetime('now','-{h_int} hours')")
        
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
                except Exception: d[f] = {} if f=="iocs" else []
            items.append(d)
        return {"total":total,"page":page,"page_size":page_size,"items":items}


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

        # Build a case-insensitive lookup map of victim groups to ensure proper casing
        victim_group_map = {}
        for row in v_rows:
            g = row["group_name"]
            if g:
                victim_group_map[g.lower().strip()] = g.strip()

        results = []
        seen_urls = {s["url"].lower() for s in await self.get_all_onion_sites(active_only=False)}
        
        # Combine and deduplicate rows in Python memory (instant!)
        for row in v_rows + i_rows:
            g = (row["group_name"] or "unknown").strip()
            u = (row["url"] or "").strip().lower()
            if g and u and ".onion" in u:
                # Apply preferred victim casing if available
                g_mapped = victim_group_map.get(g.lower(), g)
                if u not in seen_urls:
                    results.append({"group_name": g_mapped, "url": u, "last_status": "pending"})
                    seen_urls.add(u)
        return results

    async def sync_config_onions(self) -> int:
        """Ensure settings.ONION_SITES are present in onion_sites for monitoring."""
        added = 0
        for site in getattr(settings, "ONION_SITES", []):
            group = (site.get("group") or site.get("group_name") or "Unknown").strip()
            url = (site.get("url") or "").strip()
            if not group or ".onion" not in url.lower():
                continue
            if not url.lower().startswith(("http://", "https://")):
                url = f"http://{url}"
            desc = (site.get("description") or "Configured onion site").strip()
            site_type = (site.get("site_type") or "ransomware").strip()
            try:
                cur = await self._conn.execute(
                    """INSERT INTO onion_sites (group_name, url, description, site_type, active)
                       VALUES (?, ?, ?, ?, 1)
                       ON CONFLICT(url) DO UPDATE SET
                         group_name=excluded.group_name,
                         description=CASE
                           WHEN description IS NULL OR description=''
                           THEN excluded.description ELSE description END,
                         site_type=COALESCE(NULLIF(site_type,''), excluded.site_type)""",
                    (group, url, desc, site_type),
                )
                if cur.rowcount > 0:
                    added += 1
            except Exception as exc:
                logger.debug("Config onion sync skipped %s: %s", url, exc)
        await self._conn.commit()
        return added

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
        await self.sync_config_onions()
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
        try:
            await self._retry_execute(
                """UPDATE onion_sites SET 
                   page_title=?, meta_generator=?, last_content=?, full_html=?, 
                   screenshot_path=?, last_checked=?, last_status='200' 
                   WHERE id=?""",
                (title, generator, content, full_html, screenshot_path, now, site_id),
                max_retries=5
            )
            await self._retry_commit(max_retries=5)
        except Exception as e:
            logger.warning(f"Failed to update onion scrape for site {site_id}: {e}")

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
            except Exception: d["entities"] = []
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

    # ── ICS Advisory (persistent, budget-aware) ──────────────────────────────────────

    async def upsert_ics_advisory(self, record: Dict[str, Any]) -> Tuple[int, bool]:
        """
        Insert or update an ICS advisory record.
        Stores a flattened JSON snapshot (normalized_data) via pandas.json_normalize
        so any new API fields are captured automatically.
        """
        ics_number = (record.get("ics_number") or record.get("advisory_id") or "").strip()
        cve_id     = (record.get("cve_id") or "N/A").strip().upper()
        if not ics_number and cve_id == "N/A":
            return 0, False

        ts = now_iso()
        async with self._conn.execute(
            "SELECT * FROM ics_advisories WHERE ics_number=? AND cve_id=?",
            (ics_number, cve_id)
        ) as cur:
            existing = await cur.fetchone()

        existing_row = dict(existing) if existing else None

        def _json_obj(value: Any) -> Dict[str, Any]:
            try:
                parsed = json.loads(value or "{}")
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}

        def _existing_has_official_cvelist(row: Dict[str, Any]) -> bool:
            raw = _json_obj(row.get("raw_data"))
            norm = _json_obj(row.get("normalized_data"))
            return bool(raw.get("cvelist_official") or norm.get("cvelist_official"))

        def _keep_existing(column: str, *record_keys: str) -> None:
            if not existing_row:
                return
            value = existing_row.get(column)
            if _is_placeholder_text(value):
                return
            for key in record_keys:
                record[key] = value

        if existing_row and _existing_has_official_cvelist(existing_row):
            _keep_existing("vendor", "affected_vendor", "vendor")
            _keep_existing("product", "affected_application", "product")
            _keep_existing("cvss_score", "cvss_score")
            _keep_existing("severity", "cvss_severity", "severity")
            _keep_existing("cwe", "cwe")
            _keep_existing("vendor_hq", "vendor_hq")

        if existing_row and int(existing_row.get("ai_enriched") or 0) == 1:
            _keep_existing("title", "title")
            _keep_existing("impact", "impact")
            _keep_existing("affected_version", "affected_version")
            _keep_existing("fixed_version", "fixed_version")
            _keep_existing("patch_availability", "patch_availability")
            _keep_existing("poc_availability", "poc_availability")

        severity_raw = (record.get("cvss_severity") or record.get("severity") or "medium").lower()
        severity = severity_raw if severity_raw in ("critical","high","medium","low") else "medium"
        parsed_release_year, parsed_release_month = self._parse_ics_date_parts(
            record.get("release_date") or record.get("published_date") or ""
        )
        parsed_update_year, parsed_update_month = self._parse_ics_date_parts(record.get("last_updated") or "")
        release_year = self._int_or_none(record.get("release_year") or record.get("published_year") or record.get("year")) or parsed_release_year
        release_month = self._int_or_none(record.get("release_month") or record.get("published_month") or record.get("month")) or parsed_release_month
        update_year = self._int_or_none(record.get("update_year")) or parsed_update_year
        update_month = self._int_or_none(record.get("update_month")) or parsed_update_month
        cve_year = self._int_or_none(record.get("cve_year"))
        affected_version = record.get("affected_version", "")
        fixed_version = record.get("fixed_version", "")
        if _is_placeholder_text(fixed_version):
            fixed_version = _derive_fixed_version_hint(affected_version)

        normalized_record = dict(record)
        normalized_record["affected_version"] = affected_version
        normalized_record["fixed_version"] = fixed_version
        if existing_row:
            old_normalized = _json_obj(existing_row.get("normalized_data"))
            if old_normalized:
                old_normalized.update(normalized_record)
                normalized_record = old_normalized
            for key in (
                "ai_enriched",
                "patch_available_bool",
                "poc_available_bool",
                "xtron_score",
                "cve_published_date",
                "cve_updated_date",
                "cve_pub_year",
                "cve_pub_month",
                "cvelist_status",
            ):
                value = existing_row.get(key)
                if value not in (None, ""):
                    normalized_record[key] = value
            if _existing_has_official_cvelist(existing_row):
                normalized_record["cvelist_official"] = True
                normalized_record["cvelist_source"] = "CVEProject/cvelistV5"
                normalized_record["affected_vendor"] = existing_row.get("vendor") or normalized_record.get("affected_vendor", "")
                normalized_record["affected_application"] = existing_row.get("product") or normalized_record.get("affected_application", "")
                normalized_record["vendor"] = existing_row.get("vendor") or normalized_record.get("vendor", "")
                normalized_record["product"] = existing_row.get("product") or normalized_record.get("product", "")
                normalized_record["cvss_score"] = existing_row.get("cvss_score") or normalized_record.get("cvss_score", "")
                normalized_record["cvss_severity"] = (existing_row.get("severity") or normalized_record.get("cvss_severity", "") or "").capitalize()
                normalized_record["severity"] = existing_row.get("severity") or normalized_record.get("severity", "")

        # Build normalized_data using pandas for future-proof flattening
        try:
            import pandas as pd
            flat = pd.json_normalize(normalized_record, sep="_").to_dict(orient="records")
            normalized = json.dumps(flat[0] if flat else normalized_record)
        except Exception:
            normalized = json.dumps(normalized_record)

        if existing:
            await self._conn.execute(
                """UPDATE ics_advisories SET
                   title=COALESCE(NULLIF(?,''),title),
                   vendor=COALESCE(NULLIF(?,''),vendor),
                   product=COALESCE(NULLIF(?,''),product),
                   cvss_score=COALESCE(NULLIF(?,''),cvss_score),
                   severity=?,
                   release_date=COALESCE(NULLIF(?,''),release_date),
                   last_updated=COALESCE(NULLIF(?,''),last_updated),
                   release_year=COALESCE(?,release_year),
                   release_month=COALESCE(?,release_month),
                   update_year=COALESCE(?,update_year),
                   update_month=COALESCE(?,update_month),
                   cve_year=COALESCE(?,cve_year),
                   advisory_url=COALESCE(NULLIF(?,''),advisory_url),
                   sector=COALESCE(NULLIF(?,''),sector),
                   patch_availability=COALESCE(NULLIF(?,'Unknown'),patch_availability),
                   poc_availability=COALESCE(NULLIF(?,'Unknown'),poc_availability),
                   impact=COALESCE(NULLIF(?,''),impact),
                   affected_version=COALESCE(NULLIF(NULLIF(?,''),'Unknown'),affected_version),
                   fixed_version=COALESCE(NULLIF(NULLIF(?,''),'Unknown'),fixed_version),
                   cwe=COALESCE(NULLIF(?,''),cwe),
                   vendor_hq=COALESCE(NULLIF(?,''),vendor_hq),
                   product_distribution=COALESCE(NULLIF(?,''),product_distribution),
                   kev_flag=COALESCE(NULLIF(?,''),kev_flag),
                   nist_url=COALESCE(NULLIF(?,''),nist_url),
                   csaf_url=COALESCE(NULLIF(?,''),csaf_url),
                   data_source=?,
                   normalized_data=?,
                   updated_at=?
                   WHERE id=?""",
                (record.get("title",""), record.get("affected_vendor",""),
                 record.get("affected_application",""), record.get("cvss_score",""),
                 severity,
                 record.get("release_date",""), record.get("last_updated",""),
                 release_year, release_month, update_year, update_month, cve_year,
                 record.get("advisory_url",""), record.get("sector",""),
                 record.get("patch_availability","Unknown"),
                 record.get("poc_availability","Unknown"),
                 record.get("impact",""), affected_version,
                 fixed_version, record.get("cwe",""),
                 record.get("vendor_hq",""), record.get("product_distribution",""),
                 record.get("kev_flag",""),
                 record.get("nist_url",""), record.get("csaf_url",""),
                 record.get("data_source","csv"),
                 normalized, ts, existing["id"])
            )
            await self._conn.commit()
            return existing["id"], False
        else:
            cur = await self._conn.execute(
                """INSERT INTO ics_advisories
                   (ics_number, cve_id, title, vendor, product, cvss_score, severity,
                    release_date, last_updated, release_year, release_month, update_year, update_month, cve_year,
                    advisory_url, sector,
                    patch_availability, poc_availability, impact,
                    affected_version, fixed_version, cwe,
                    vendor_hq, product_distribution, kev_flag, nist_url, csaf_url, data_source,
                    raw_data, normalized_data, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ics_number, cve_id,
                 record.get("title",""), record.get("affected_vendor",""),
                 record.get("affected_application",""), record.get("cvss_score",""),
                 severity,
                 record.get("release_date",""), record.get("last_updated",""),
                 release_year, release_month, update_year, update_month, cve_year,
                 record.get("advisory_url",""), record.get("sector",""),
                 record.get("patch_availability","Unknown"),
                 record.get("poc_availability","Unknown"),
                 record.get("impact",""),
                 affected_version, fixed_version,
                 record.get("cwe",""), record.get("vendor_hq",""),
                 record.get("product_distribution",""), record.get("kev_flag",""),
                 record.get("nist_url",""), record.get("csaf_url",""),
                 record.get("data_source","csv"),
                 json.dumps(record), normalized, ts, ts)
            )
            await self._conn.commit()
            return cur.lastrowid, True

    async def backfill_ics_fixed_versions(self) -> int:
        """Populate fixed_version from affected_version where a version bound exists."""
        try:
            async with self._conn.execute(
                """SELECT id, affected_version, fixed_version, normalized_data
                   FROM ics_advisories
                   WHERE affected_version IS NOT NULL AND TRIM(affected_version) != ''"""
            ) as cur:
                rows = await cur.fetchall()

            updated = 0
            for row in rows:
                if not _is_placeholder_text(row["fixed_version"]):
                    continue
                hint = _derive_fixed_version_hint(row["affected_version"])
                if _is_placeholder_text(hint):
                    continue
                normalized_data = row["normalized_data"]
                if normalized_data:
                    try:
                        normalized_obj = json.loads(normalized_data)
                        if isinstance(normalized_obj, dict):
                            normalized_obj["fixed_version"] = hint
                            normalized_data = json.dumps(normalized_obj)
                    except Exception:
                        pass
                await self._conn.execute(
                    "UPDATE ics_advisories SET fixed_version=?, normalized_data=COALESCE(NULLIF(?,''),normalized_data), updated_at=? WHERE id=?",
                    (hint, normalized_data or "", now_iso(), row["id"])
                )
                updated += 1

            if updated:
                await self._conn.commit()
            return updated
        except Exception as exc:
            logger.debug("ICS fixed-version backfill skipped: %s", exc)
            return 0

    @staticmethod
    def _int_or_none(value: Any) -> Optional[int]:
        try:
            if value is None or str(value).strip() == "":
                return None
            return int(float(str(value).strip()))
        except Exception:
            return None

    @staticmethod
    def _parse_ics_date_parts(value: Any) -> Tuple[Optional[int], Optional[int]]:
        text = str(value or "").strip()
        if not text:
            return None, None
        text = text.split("T")[0].replace("\u2013", "-").replace("\u2014", "-")
        month_names = {
            "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
            "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
        }
        match = re.match(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text)
        if match:
            return int(match.group(1)), int(match.group(2))
        match = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})", text)
        if match:
            return int(match.group(3)), int(match.group(1))
        match = re.match(r"^([A-Za-z]+)\s+\d{1,2},?\s+(\d{4})", text)
        if match:
            month = month_names.get(match.group(1).lower()[:3])
            return int(match.group(2)), month
        match = re.match(r"^\d{1,2}\s+([A-Za-z]+),?\s+(\d{4})", text)
        if match:
            month = month_names.get(match.group(1).lower()[:3])
            return int(match.group(2)), month
        return None, None

    async def get_ics_advisories(
        self, page=1, page_size=100,
        year: int = None, month: int = None,
        severity: str = None, vendor: str = None,
        search: str = None, cve_id: str = None,
        filter_mode: str = "advisory",
    ) -> Dict:
        """
        Query the persistent ICS advisory table with safe filtering.

        filter_mode='advisory'      — filter by ICS advisory release date
                                      (release_year / release_month columns)
        filter_mode='cve_published' — filter by the official CVE publish date
                                      from the CVEProject/cvelistV5 GitHub repo
                                      (cve_pub_year / cve_pub_month columns)
        """
        where, params = [], []
        use_cve_pub = (filter_mode == "cve_published")

        # ── Year / Month filter expressions ──────────────────────────────────
        # Advisory-release path: parse release_date (M/D/YYYY or YYYY-MM-DD)
        # falling back to pre-computed release_year/release_month columns.
        rel_year_expr = """COALESCE(release_year, CAST(
            CASE
                WHEN substr(trim(release_date), 5, 1) = '-'
                    THEN substr(trim(release_date), 1, 4)
                WHEN instr(trim(release_date), '/') > 0
                    THEN substr(trim(release_date), length(trim(release_date))-3, 4)
                ELSE NULL
            END AS INTEGER))"""

        rel_month_expr = """COALESCE(release_month, CAST(
            CASE
                WHEN substr(trim(release_date), 5, 1) = '-'
                    THEN substr(trim(release_date), 6, 2)
                WHEN instr(trim(release_date), '/') > 0
                    THEN substr(trim(release_date), 1, instr(trim(release_date), '/')-1)
                WHEN lower(substr(trim(release_date), 1, 3)) = 'jan' THEN '1'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'feb' THEN '2'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'mar' THEN '3'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'apr' THEN '4'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'may' THEN '5'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'jun' THEN '6'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'jul' THEN '7'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'aug' THEN '8'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'sep' THEN '9'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'oct' THEN '10'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'nov' THEN '11'
                WHEN lower(substr(trim(release_date), 1, 3)) = 'dec' THEN '12'
                ELSE NULL
            END AS INTEGER))"""

        # Sort always uses advisory release date for stable ordering.
        sort_year_expr  = rel_year_expr
        sort_month_expr = rel_month_expr

        # ── Filters ──────────────────────────────────────────────────────────
        if year:
            if use_cve_pub:
                # CVE Published Date mode: use cve_pub_year from cvelistV5 zip
                where.append("(cve_pub_year = ?)")
            else:
                # Advisory Release Date mode: use ICS advisory release_year
                where.append(f"({rel_year_expr} = ?)")
            params.append(int(year))

        if month:
            if use_cve_pub:
                # CVE Published Date mode: use cve_pub_month from cvelistV5 zip
                where.append("(cve_pub_month = ?)")
            else:
                # Advisory Release Date mode: use ICS advisory release_month
                where.append(f"({rel_month_expr} = ?)")
            params.append(int(month))

        if severity:
            where.append("LOWER(severity) = LOWER(?)")
            params.append(severity)

        if vendor:
            where.append("LOWER(vendor) LIKE LOWER(?)")
            params.append(f"%{vendor}%")

        if cve_id and not search:
            where.append("LOWER(cve_id) LIKE LOWER(?)")
            params.append(f"%{cve_id}%")

        if search:
            where.append(
                "(LOWER(title) LIKE LOWER(?) OR LOWER(vendor) LIKE LOWER(?) "
                "OR LOWER(product) LIKE LOWER(?) OR LOWER(cve_id) LIKE LOWER(?) "
                "OR LOWER(ics_number) LIKE LOWER(?))"
            )
            params += [f"%{search}%"] * 5

        ws  = ("WHERE " + " AND ".join(where)) if where else ""
        off = (page - 1) * page_size

        sort_expr = (
            f"printf('%04d-%02d-01', COALESCE({sort_year_expr}, 0),"
            f" COALESCE({sort_month_expr}, 0))"
        )

        try:
            async with self._conn.execute(f"SELECT COUNT(*) FROM ics_advisories {ws}", params) as cur:
                total_row = await cur.fetchone()
                total = total_row[0] if total_row else 0

            async with self._conn.execute(
                f"SELECT * FROM ics_advisories {ws} ORDER BY {sort_expr} DESC, ics_number DESC LIMIT ? OFFSET ?",
                params + [page_size, off]
            ) as cur:
                rows = await cur.fetchall()

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "items": [dict(r) for r in rows],
                "filter_mode": filter_mode,
            }
        except Exception as e:
            logger.error("ICS advisory query failed: %s", e)
            return {"total": 0, "page": page, "page_size": page_size, "items": [], "error": str(e)}


    async def get_ics_meta(self) -> Dict:
        """
        Return years, months, severities, vendors and total count from stored
        ICS advisories.  Returns two sets of year/month options:
          - years / months           — based on ICS advisory release date
          - cve_pub_years / cve_pub_months — based on CVE publish date from cvelistV5
        """
        total = await self._query_val("SELECT COUNT(*) FROM ics_advisories")
        vendors = await self._query_list(
            "SELECT DISTINCT vendor FROM ics_advisories WHERE vendor != '' ORDER BY vendor LIMIT 300"
        )
        sevs = await self._query_list(
            "SELECT severity, COUNT(*) as cnt FROM ics_advisories GROUP BY severity"
        )
        month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                       'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

        # ── Advisory release year/month ──────────────────────────────────────
        adv_rows = await self._query_list(
            """SELECT DISTINCT release_year, release_month
               FROM ics_advisories
               WHERE release_year IS NOT NULL AND release_month IS NOT NULL"""
        )
        adv_year_set  = set()
        adv_month_set = set()
        for row in adv_rows:
            y = self._int_or_none(row.get("release_year"))
            m = self._int_or_none(row.get("release_month"))
            if y and y > 1990: adv_year_set.add(y)
            if m and 1 <= m <= 12: adv_month_set.add(m)

        # ── CVE published year/month (from cvelistV5 enrichment) ─────────────
        pub_rows = await self._query_list(
            """SELECT DISTINCT cve_pub_year, cve_pub_month
               FROM ics_advisories
               WHERE cve_pub_year IS NOT NULL AND cve_pub_month IS NOT NULL"""
        )
        pub_year_set  = set()
        pub_month_set = set()
        for row in pub_rows:
            y = self._int_or_none(row.get("cve_pub_year"))
            m = self._int_or_none(row.get("cve_pub_month"))
            if y and y > 1990: pub_year_set.add(y)
            if m and 1 <= m <= 12: pub_month_set.add(m)

        # Count how many rows have been enriched from cvelist
        enriched_count = await self._query_val(
            "SELECT COUNT(*) FROM ics_advisories WHERE cvelist_status='done'"
        ) or 0

        return {
            "total": total or 0,
            # Advisory release date filter options
            "years":  sorted(adv_year_set,  reverse=True),
            "months": [[m, month_names[m-1]] for m in sorted(adv_month_set)],
            # CVE published date filter options (from cvelistV5)
            "cve_pub_years":  sorted(pub_year_set,  reverse=True),
            "cve_pub_months": [[m, month_names[m-1]] for m in sorted(pub_month_set)],
            "cvelist_enriched": enriched_count,
            "vendors":    [r["vendor"] for r in vendors],
            "by_severity": sevs,
        }

    # ── Status History (uptime logging for all monitored infra) ─────────────────

    async def add_status_history(
        self,
        target_type: str,
        target_id: int,
        name: str,
        url: str,
        status: str,
        latency_ms: Optional[int] = None
    ) -> int:
        """
        Log a single uptime check for any monitored target.
        target_type: 'onion_site' | 'breach_market' | 'dls'
        status: HTTP status code string, 'online', 'offline', 'timeout', etc.
        """
        try:
            cur = await self._retry_execute(
                """INSERT INTO status_history
                   (target_type, target_id, name, url, status, latency_ms, timestamp)
                   VALUES (?,?,?,?,?,?,?)""",
                (target_type, target_id, name, url, status, latency_ms, now_iso()),
                max_retries=3
            )
            await self._retry_commit(max_retries=3)
            return cur.lastrowid
        except Exception as e:
            logger.debug(f"Failed to add status history: {e}")
            return 0

    async def get_status_history(
        self,
        target_type: str = None,
        target_id: int = None,
        name: str = None,
        limit: int = 500,
        hours: int = None
    ) -> List[Dict]:
        """
        Retrieve uptime history for pattern analysis.
        Can filter by target_type, target_id, name, or a time window.
        """
        where, params = [], []
        if target_type:
            where.append("target_type=?")
            params.append(target_type)
        if target_id is not None:
            where.append("target_id=?")
            params.append(target_id)
        if name:
            where.append("name LIKE ?")
            params.append(f"%{name}%")
        if hours:
            where.append("timestamp >= datetime('now',?)")
            params.append(f"-{hours} hours")
        ws = ("WHERE " + " AND ".join(where)) if where else ""
        async with self._conn.execute(
            f"SELECT * FROM status_history {ws} ORDER BY timestamp DESC LIMIT ?",
            params + [limit]
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_uptime_summary(
        self,
        target_type: str = None,
        hours: int = 168  # last 7 days by default
    ) -> List[Dict]:
        """
        Returns per-target uptime summary: total checks, online count, offline count.
        Useful for dashboards showing uptime % over time.
        """
        where, params = ["timestamp >= datetime('now',?)"], [f"-{hours} hours"]
        if target_type:
            where.append("target_type=?")
            params.append(target_type)
        ws = "WHERE " + " AND ".join(where)
        rows = await self._query_list(
            f"""SELECT
                   target_type, target_id, name, url,
                   COUNT(*) as total_checks,
                   SUM(CASE WHEN status IN ('200','online') THEN 1 ELSE 0 END) as online_count,
                   SUM(CASE WHEN status NOT IN ('200','online') THEN 1 ELSE 0 END) as offline_count,
                   MAX(timestamp) as last_check,
                   MIN(timestamp) as first_check
               FROM status_history {ws}
               GROUP BY target_type, target_id
               ORDER BY name ASC""",
        )
        # Compute uptime_pct
        for r in rows:
            t = r.get("total_checks") or 1
            r["uptime_pct"] = round(100.0 * r.get("online_count", 0) / t, 1)
        return rows

    # ── HIBR Searches ─────────────────────────────────────────────────────────────

    async def get_hibr_search(self, query: str, query_type: str) -> Optional[Dict]:
        """Get cached HIBR search results."""
        async with self._conn.execute(
            "SELECT results_json, updated_at FROM hibr_searches WHERE query=? AND query_type=?",
            (query, query_type)
        ) as cur:
            rows = await cur.fetchall()
        if not rows:
            return None
        import json
        try:
            res = json.loads(rows[0]["results_json"])
            res["_cached_at"] = rows[0]["updated_at"]
            return res
        except Exception as e:
            logger.error("Failed to parse cached HIBR search: %s", e)
            return None

    async def save_hibr_search(self, query: str, query_type: str, results_json: str) -> None:
        """Save or update HIBR search results."""
        try:
            await self._retry_execute(
                """INSERT INTO hibr_searches (query, query_type, results_json, updated_at)
                   VALUES (?, ?, ?, datetime('now'))
                   ON CONFLICT(query, query_type) DO UPDATE SET
                   results_json = excluded.results_json,
                   updated_at = excluded.updated_at
                """,
                (query, query_type, results_json),
                max_retries=3
            )
            await self._retry_commit(max_retries=3)
        except Exception as e:
            logger.error("Failed to save HIBR search cache: %s", e)
