import sqlite3, json

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check CVSS score vs severity mismatch
print("=== CVSS Score vs Severity Mismatch Check ===\n")
cursor.execute("SELECT cve_id, ics_number, cvss_score, severity, normalized_data FROM ics_advisories LIMIT 20")
rows = cursor.fetchall()

for r in rows:
    nd = json.loads(r['normalized_data'] or '{}')
    db_cvss = r['cvss_score']
    db_severity = r['severity']
    nd_cvss = nd.get('cvss_score', 'N/A')
    nd_severity = nd.get('cvss_severity', 'N/A')
    nd_vendor = nd.get('affected_vendor', 'N/A')
    nd_product = nd.get('affected_application', 'N/A')
    
    mismatch = ""
    if str(db_cvss) != str(nd_cvss):
        mismatch += f" [CVSS MISMATCH: DB={db_cvss} vs ND={nd_cvss}]"
    if db_severity and nd_severity and db_severity.lower() != nd_severity.lower():
        mismatch += f" [SEVERITY MISMATCH: DB={db_severity} vs ND={nd_severity}]"
    
    print(f"{r['cve_id']} | {r['ics_number']}")
    print(f"  DB:  cvss={db_cvss}, severity={db_severity}")
    print(f"  ND:  cvss={nd_cvss}, severity={nd_severity}")
    if mismatch:
        print(f"  *** {mismatch}")
    print()

# Also check: are multiple CVEs sharing same cumulative CVSS?
print("\n=== Same Advisory, Multiple CVEs (Cumulative CVSS issue) ===\n")
cursor.execute("""
    SELECT ics_number, COUNT(*) as cnt, GROUP_CONCAT(cve_id) as cves, cvss_score, severity
    FROM ics_advisories
    GROUP BY ics_number
    HAVING cnt > 1
    LIMIT 10
""")
for r in cursor.fetchall():
    print(f"{r['ics_number']}: {r['cnt']} CVEs, CVSS={r['cvss_score']}, Sev={r['severity']}")
    print(f"  CVEs: {r['cves']}")
    print()
