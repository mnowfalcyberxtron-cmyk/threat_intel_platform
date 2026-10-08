import sqlite3
import json

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

cursor.execute("SELECT cve_id, vendor, product, title, vendor_hq, cvss_score, severity FROM ics_advisories WHERE cve_id IN ('CVE-2026-3014', 'CVE-2026-23573', 'CVE-2026-59839')")
rows = cursor.fetchall()

print("--- VERIFICATION OF FIXED CVEs ---")
for r in rows:
    print(r)

conn.close()
