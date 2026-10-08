import sqlite3, sys
sys.stdout.reconfigure(encoding='utf-8')

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Check xtron=70 high rows
cur.execute("""SELECT cve_id, cvss_score, severity, xtron_score, poc_available_bool, kev_flag, affected_version, fixed_version
FROM ics_advisories WHERE xtron_score=70 AND LOWER(severity)='high' LIMIT 10""")
print('XTRON=70, severity=high:')
for r in cur.fetchall():
    print(dict(r))

# Check rows where fixed_version starts with 'Fixed:'
cur.execute("""SELECT cve_id, fixed_version, affected_version FROM ics_advisories
WHERE fixed_version LIKE 'Fixed:%' OR affected_version LIKE 'Affected:%' LIMIT 10""")
print('\nRows with Fixed:/Affected: prefix:')
for r in cur.fetchall():
    print(dict(r))

# Check non-enriched rows with patch_availability=Yes but no bool set  
cur.execute("""SELECT COUNT(*) as cnt FROM ics_advisories
WHERE (patch_available_bool IS NULL OR patch_available_bool = '')
  AND patch_availability = 'Yes'""")
r = cur.fetchone()
print(f'\nNon-enriched rows with patch_availability=Yes: {r["cnt"]}')

# Sample recent rows (Jul 2026+) to check status
cur.execute("""SELECT cve_id, cvss_score, severity, ai_enriched, patch_available_bool, poc_available_bool, xtron_score
FROM ics_advisories 
WHERE cve_published_date >= '2026-07-01' 
ORDER BY cve_published_date DESC LIMIT 10""")
print('\nRecent rows (Jul 2026+):')
for r in cur.fetchall():
    print(dict(r))

conn.close()
