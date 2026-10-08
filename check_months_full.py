import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
c = conn.cursor()

# Show all data grouped by actual release_year + release_month
# so we can see what's really in July 2026

print("=== Full breakdown by release_year + release_month (DB stored columns) ===")
rows = c.execute("""
    SELECT release_year, release_month, COUNT(*) as cnt
    FROM ics_advisories
    WHERE release_year IS NOT NULL AND release_month IS NOT NULL
    GROUP BY release_year, release_month
    ORDER BY release_year, release_month
""").fetchall()

total = 0
for r in rows:
    total += r[2]
    print(f"  {r[0]}-{str(r[1]).zfill(2)}  =>  {r[2]} advisories")

print(f"\n  GRAND TOTAL: {total}")

# Now specifically look at July 2026 - show sample dates
print("\n=== Sample July 2026 rows (release_date column raw) ===")
sample = c.execute("""
    SELECT release_date, COUNT(*) as cnt
    FROM ics_advisories
    WHERE release_year = 2026 AND release_month = 7
    GROUP BY release_date
    ORDER BY release_date
""").fetchall()
for r in sample:
    print(f"  release_date='{r[0]}'  count={r[1]}")
