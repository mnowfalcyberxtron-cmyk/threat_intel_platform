import re

with open('database/db.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Imports
content = content.replace('import aiosqlite', 'import asyncpg\nimport urllib.parse')
content = content.replace('import sqlite3', '')

# 2. Connection string
content = content.replace('self._db_path = settings.DB_PATH',
                          'self._db_url = getattr(settings, "DATABASE_URL", "")\n        self._db_path = settings.DB_PATH')

init_old = '''    async def initialize(self):
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path, timeout=60.0)
        self._conn.row_factory = aiosqlite.Row
        
        # Performance optimization PRAGMAs
        await self._conn.execute("PRAGMA journal_mode=WAL")                # Write-Ahead Logging
        await self._conn.execute("PRAGMA busy_timeout=60000")              # 60 second timeout
        await self._conn.execute("PRAGMA synchronous=NORMAL")              # Balance speed/safety
        await self._conn.execute("PRAGMA foreign_keys=ON")                 # Enforce FK constraints
        await self._conn.execute("PRAGMA cache_size=-131072")              # 128MB cache
        await self._conn.execute("PRAGMA page_size=4096")                  # 4KB pages
        await self._conn.execute("PRAGMA wal_autocheckpoint=2000")         # Checkpoint every 2000 pages
        await self._conn.execute("PRAGMA temp_store=MEMORY")               # Temp tables in memory
        await self._conn.execute("PRAGMA query_only=OFF")                  # Allow writes
        await self._conn.execute("PRAGMA mmap_size=30000000")              # 30MB mmap'''
        
init_new = '''    async def initialize(self):
        db_url = getattr(settings, "DATABASE_URL", None)
        if not db_url:
            db_url = "postgresql://postgres:postgres@localhost:5432/threatintel"
            
        pg_conn = await asyncpg.connect(db_url)
        self._conn = ConnectionWrapper(pg_conn)'''

content = content.replace(init_old, init_new)

wrapper_code = '''
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
'''

content = content.replace('class Database:', wrapper_code + '\\nclass Database:')
content = content.replace('sqlite3.OperationalError', 'asyncpg.exceptions.PostgresError')

with open('database/db_pg.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Wrote db_pg.py')
