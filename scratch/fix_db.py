import sys

with open('e:/threat_intel_platform/database/db.py', 'r', encoding='utf-8') as f:
    content = f.read()

correct_code = '''    async def _seed_sources(self):
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
        return min(round(base+multi+rec, 3), 1.0)'''

prefix = content.split('    async def _seed_sources(self):')[0]
suffix = content.split('    def _clabel(self, s: float) -> str:')[1]

new_content = prefix + correct_code + '\n\n    def _clabel(self, s: float) -> str:' + suffix

with open('e:/threat_intel_platform/database/db.py', 'w', encoding='utf-8') as f:
    f.write(new_content)
print('Fixed!')
