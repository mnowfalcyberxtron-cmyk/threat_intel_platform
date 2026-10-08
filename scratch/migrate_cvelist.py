import sqlite3, time

DB = 'data/threat_intel.db'
con = sqlite3.connect(DB, timeout=30)
cur = con.cursor()

migrations = [
    "ALTER TABLE ics_advisories ADD COLUMN cve_published_date TEXT",
    "ALTER TABLE ics_advisories ADD COLUMN cve_updated_date   TEXT",
    "ALTER TABLE ics_advisories ADD COLUMN cve_pub_year       INTEGER",
    "ALTER TABLE ics_advisories ADD COLUMN cve_pub_month      INTEGER",
    "ALTER TABLE ics_advisories ADD COLUMN cvelist_status     TEXT DEFAULT 'pending'",
]

# Check existing columns first
cur.execute('PRAGMA table_info(ics_advisories)')
existing = {r[1] for r in cur.fetchall()}

for sql in migrations:
    col = sql.split('ADD COLUMN')[1].strip().split()[0]
    if col in existing:
        print(f'SKIP (exists): {col}')
        continue
    cur.execute(sql)
    print(f'OK: {sql[:70]}')

# Index for fast filtering
cur.execute('CREATE INDEX IF NOT EXISTS idx_ics_cve_pub_ym ON ics_advisories(cve_pub_year, cve_pub_month)')
print('OK: index created')

con.commit()

# Mark all rows as pending
cur.execute("UPDATE ics_advisories SET cvelist_status='pending' WHERE cvelist_status IS NULL OR cvelist_status=''")
con.commit()
print(f'Marked {cur.rowcount} rows as pending for cvelist enrichment')

# Verify final schema
cur.execute('PRAGMA table_info(ics_advisories)')
print('Final columns:', [r[1] for r in cur.fetchall()])
con.close()
print('Migration DONE.')
