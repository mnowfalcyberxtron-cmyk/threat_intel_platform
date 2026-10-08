import sqlite3
import os
import json

DB_PATH = "data/threat_intel.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT id, ics_number, cve_id FROM ics_advisories WHERE cve_id != 'N/A' AND cve_id != ''")
rows = cursor.fetchall()
cve_ids = []
for row in rows:
    cves = [c.strip() for c in row[2].split(",")]
    for cve in cves:
        if cve.startswith("CVE-"):
            cve_ids.append(cve)

cve_ids = list(set(cve_ids))
print(f"Total rows: {len(rows)}")
print(f"Total unique CVEs: {len(cve_ids)}")
print(f"Some CVEs: {cve_ids[:10]}")

with open("cves_to_process.json", "w") as f:
    json.dump(cve_ids, f)
