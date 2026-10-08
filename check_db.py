import sqlite3
conn = sqlite3.connect('e:/threat_intel_platform/data/threat_intel.db')
print("=== Monthly counts ===")
for row in conn.execute("SELECT strftime('%Y-%m', release_date) as month, count(*) FROM ics_advisories GROUP BY month ORDER BY month DESC LIMIT 5;").fetchall():
    print(row)

print("\n=== May 2026 sample (correct cols) ===")
for row in conn.execute("SELECT ics_number, cve_id, release_date, nist_url, data_source FROM ics_advisories WHERE release_date LIKE '2026-05-%' LIMIT 5;").fetchall():
    print(row)

print("\n=== Total count ===")
print(conn.execute("SELECT count(*) FROM ics_advisories").fetchone())

print("\n=== Recent ics_numbers from 2026 ===")
for row in conn.execute("SELECT ics_number, cve_id, release_date FROM ics_advisories WHERE release_date LIKE '2026-%' ORDER BY release_date DESC LIMIT 10;").fetchall():
    print(row)
