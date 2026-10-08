import sqlite3

con = sqlite3.connect('e:/threat_intel_platform/data/threat_intel.db')
con.row_factory = sqlite3.Row
cur = con.cursor()

# Check the most recent dates and their formats
cur.execute("SELECT release_date FROM ics_advisories WHERE release_date != '' ORDER BY rowid DESC LIMIT 30")
rows = cur.fetchall()
print("=== RECENT release_date VALUES ===")
for r in rows:
    print(repr(r[0]))

# Count by year using different methods
print("\n=== COUNT BY YEAR (strftime) ===")
cur.execute("SELECT strftime('%Y', release_date) as yr, COUNT(*) FROM ics_advisories GROUP BY yr ORDER BY yr DESC LIMIT 10")
for r in cur.fetchall():
    print(r[0], r[1])

print("\n=== COUNT BY YEAR (substr) ===")
cur.execute("SELECT substr(release_date,1,4) as yr, COUNT(*) FROM ics_advisories GROUP BY yr ORDER BY yr DESC LIMIT 10")
for r in cur.fetchall():
    print(r[0], r[1])

# Check May 2026 specifically
print("\n=== MAY 2026 CHECK (strftime) ===")
cur.execute("SELECT COUNT(*) FROM ics_advisories WHERE CAST(strftime('%Y', release_date) AS INTEGER)=2026 AND CAST(strftime('%m', release_date) AS INTEGER)=5")
print("count:", cur.fetchone()[0])

print("\n=== MAY 2026 CHECK (substr) ===")
cur.execute("SELECT COUNT(*) FROM ics_advisories WHERE substr(release_date,1,4)='2026' AND (substr(release_date,6,2)='05' OR substr(release_date,6,2)='5/')")
print("count:", cur.fetchone()[0])

print("\n=== TOTAL RECORDS ===")
cur.execute("SELECT COUNT(*) FROM ics_advisories")
print("total:", cur.fetchone()[0])

print("\n=== MAX DATE ===")
cur.execute("SELECT MAX(release_date) FROM ics_advisories")
print("max:", cur.fetchone()[0])

con.close()
