import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

print("=== July 2026 AI fields sample ===")
cursor.execute("""
SELECT cve_id, impact, patch_available_bool, poc_available_bool, xtron_score, ai_enriched 
FROM ics_advisories WHERE release_date >= '2026-07-01' LIMIT 10
""")
rows = cursor.fetchall()
for r in rows:
    print(f'CVE:{r[0]} | impact:{str(r[1])[:60]} | patch_bool:{r[2]} | poc_bool:{r[3]} | xtron:{r[4]} | ai:{r[5]}')

print("\n=== Rows with proper AI narrative in impact ===")
cursor.execute("""
SELECT COUNT(*) FROM ics_advisories WHERE impact LIKE 'A successful exploit%'
""")
print('With proper impact narrative:', cursor.fetchone()[0])

print("\n=== Stats for fields ===")
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE patch_available_bool IS NOT NULL AND patch_available_bool != ''")
print('patch_available_bool filled:', cursor.fetchone()[0])
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE xtron_score IS NOT NULL")
print('xtron_score filled:', cursor.fetchone()[0])

print("\n=== Sample where patch_available_bool IS filled ===")
cursor.execute("""
SELECT cve_id, impact, patch_available_bool, poc_available_bool, xtron_score FROM ics_advisories 
WHERE patch_available_bool IS NOT NULL AND patch_available_bool != '' LIMIT 3
""")
for r in cursor.fetchall():
    print(f'  CVE:{r[0]} | impact:{str(r[1])[:60]} | patch_bool:{r[2]} | poc_bool:{r[3]} | xtron:{r[4]}')

print("\n=== Month distribution 2026-07 ===")
cursor.execute("""
SELECT COUNT(*) FROM ics_advisories WHERE release_date LIKE '2026-07%'
""")
print('Release date July 2026:', cursor.fetchone()[0])

cursor.execute("""
SELECT release_year, release_month, COUNT(*) 
FROM ics_advisories GROUP BY release_year, release_month 
ORDER BY release_year DESC, release_month DESC LIMIT 10
""")
print('\nMonthly distribution:')
for r in cursor.fetchall():
    print(f'  {r[0]}-{str(r[1]).zfill(2)}: {r[2]}')

conn.close()
