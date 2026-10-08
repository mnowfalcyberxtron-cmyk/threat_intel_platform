import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched IS NULL OR ai_enriched = 0")
print('Not AI enriched:', cursor.fetchone()[0])

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched = 1")
print('AI enriched:', cursor.fetchone()[0])

cursor.execute('SELECT COUNT(*) FROM ics_advisories')
print('Total:', cursor.fetchone()[0])

cursor.execute("SELECT cve_id, ai_enriched, impact, patch_availability, poc_availability, affected_version, fixed_version, patch_available_bool, poc_available_bool, xtron_score FROM ics_advisories WHERE ai_enriched = 1 LIMIT 3")
rows = cursor.fetchall()
print('\n--- AI enriched rows ---')
for r in rows:
    print(f'CVE: {r[0]} | ai_enriched: {r[1]} | impact[:80]: {str(r[2])[:80]} | patch_bool: {r[7]} | poc_bool: {r[8]} | xtron: {r[9]}')

# Check fields that are missing
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched = 1 AND (impact IS NULL OR impact = '')")
print('\nAI enriched but impact empty:', cursor.fetchone()[0])
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched = 1 AND (affected_version IS NULL OR affected_version = '')")
print('AI enriched but affected_version empty:', cursor.fetchone()[0])

# Sample unenriched rows to see what date criteria looks like
cursor.execute("SELECT cve_id, cve_published_date, ai_enriched FROM ics_advisories WHERE (ai_enriched IS NULL OR ai_enriched = 0) LIMIT 5")
print('\n--- Unenriched rows sample ---')
for r in cursor.fetchall():
    print(f'CVE: {r[0]} | cve_published_date: {r[1]} | ai_enriched: {r[2]}')

# Check date distribution for unenriched
cursor.execute("SELECT cve_pub_year, COUNT(*) FROM ics_advisories WHERE (ai_enriched IS NULL OR ai_enriched = 0) GROUP BY cve_pub_year ORDER BY cve_pub_year")
print('\n--- Unenriched by year ---')
for r in cursor.fetchall():
    print(f'Year: {r[0]}, Count: {r[1]}')

# The crucial check: how many meet the >= 2026-07-01 criteria but are unenriched?
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE (ai_enriched IS NULL OR ai_enriched = 0) AND cve_published_date >= '2026-07-01'")
print('\nUnenriched AND cve_pub_date >= 2026-07-01:', cursor.fetchone()[0])

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE release_date >= '2026-07-01' AND (ai_enriched IS NULL OR ai_enriched = 0)")
print('Unenriched AND release_date >= 2026-07-01:', cursor.fetchone()[0])
