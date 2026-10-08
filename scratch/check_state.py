import sqlite3, json

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Sample enriched rows
cur.execute('SELECT cve_id, cvss_score, severity, patch_available_bool, poc_available_bool, xtron_score, ai_enriched, affected_version, fixed_version, vendor, product, title FROM ics_advisories WHERE ai_enriched=1 LIMIT 5')
rows = cur.fetchall()
print('=== AI-Enriched Sample ===')
for r in rows:
    d = dict(r)
    print(d)

# Check severity distribution
cur.execute('SELECT severity, COUNT(*) as cnt FROM ics_advisories GROUP BY severity ORDER BY cnt DESC')
print('\n=== Severity Distribution ===')
for r in cur.fetchall():
    print(r['severity'], '->', r['cnt'])

# Check CVSS score vs severity — common mismatches
sql = """
SELECT cve_id, cvss_score, severity
FROM ics_advisories
WHERE cvss_score IS NOT NULL AND cvss_score != ''
  AND (
      (CAST(cvss_score AS FLOAT) >= 9.0 AND LOWER(severity) NOT IN ('critical'))
   OR (LOWER(severity) = 'critical' AND CAST(cvss_score AS FLOAT) < 9.0)
   OR (CAST(cvss_score AS FLOAT) >= 7.0 AND CAST(cvss_score AS FLOAT) < 9.0 AND LOWER(severity) NOT IN ('high'))
  )
LIMIT 20
"""
cur.execute(sql)
rows = cur.fetchall()
print('\n=== CVSS/Severity Potential Mismatches (sample) ===')
for r in rows:
    print(f"  CVE={r['cve_id']} CVSS={r['cvss_score']} Severity={r['severity']}")

# Check patch_available_bool vs patch_availability consistency
cur.execute("""
SELECT patch_availability, patch_available_bool, COUNT(*) as cnt
FROM ics_advisories
GROUP BY patch_availability, patch_available_bool
ORDER BY cnt DESC
LIMIT 20
""")
print('\n=== Patch Availability Alignment ===')
for r in cur.fetchall():
    print(f"  patch_availability={r['patch_availability']!r} | patch_available_bool={r['patch_available_bool']!r} -> {r['cnt']}")

# Check XTRON score distribution
cur.execute('SELECT xtron_score, severity, COUNT(*) as cnt FROM ics_advisories WHERE ai_enriched=1 GROUP BY xtron_score, severity ORDER BY xtron_score DESC LIMIT 20')
print('\n=== XTRON Score Distribution (enriched rows) ===')
for r in cur.fetchall():
    print(f"  XTRON={r['xtron_score']} | Severity={r['severity']} | count={r['cnt']}")

conn.close()
