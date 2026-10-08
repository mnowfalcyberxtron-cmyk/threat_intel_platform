import sqlite3, sys
sys.stdout.reconfigure(encoding='utf-8')

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

cur.execute('SELECT severity, COUNT(*) as cnt FROM ics_advisories GROUP BY severity ORDER BY cnt DESC')
print('Severity distribution:')
for r in cur.fetchall():
    print(' ', repr(r['severity']), '->', r['cnt'])

cur.execute("""SELECT cvss_score, severity, cve_id FROM ics_advisories
WHERE cvss_score IS NOT NULL AND cvss_score != ''
  AND CAST(cvss_score AS FLOAT) >= 9.0
  AND LOWER(severity) NOT IN ('critical')
LIMIT 10""")
rows = cur.fetchall()
print('CVSS>=9.0 but not Critical:')
for r in rows:
    print(' ', r['cve_id'], r['cvss_score'], r['severity'])

cur.execute("""SELECT cvss_score, severity, cve_id FROM ics_advisories
WHERE cvss_score IS NOT NULL AND cvss_score != ''
  AND LOWER(severity) = 'critical'
  AND CAST(cvss_score AS FLOAT) < 9.0
LIMIT 10""")
rows = cur.fetchall()
print('Critical but CVSS<9:')
for r in rows:
    print(' ', r['cve_id'], r['cvss_score'], r['severity'])

cur.execute("""SELECT xtron_score, severity, COUNT(*) as cnt
FROM ics_advisories WHERE ai_enriched=1
GROUP BY xtron_score, severity ORDER BY xtron_score DESC LIMIT 15""")
print('XTRON score distribution (enriched rows):')
for r in cur.fetchall():
    print(' ', r['xtron_score'], '|', r['severity'], '->', r['cnt'])

cur.execute("""SELECT patch_availability, patch_available_bool, COUNT(*) as cnt
FROM ics_advisories
GROUP BY patch_availability, patch_available_bool
ORDER BY cnt DESC LIMIT 20""")
print('Patch availability alignment:')
for r in cur.fetchall():
    print(f"  patch_avail={r['patch_availability']!r} | bool={r['patch_available_bool']!r} -> {r['cnt']}")

conn.close()
