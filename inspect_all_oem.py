import sqlite3
import json

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

query = """
SELECT cve_id, title, vendor, product, raw_data 
FROM ics_advisories 
WHERE raw_data LIKE '%Milestone%' 
   OR raw_data LIKE '%Fortinet%' 
   OR title LIKE '%Milestone%' 
   OR title LIKE '%Fortinet%' 
   OR raw_data LIKE '%Siveillance%'
   OR title LIKE '%Siveillance%'
"""
cursor.execute(query)
rows = cursor.fetchall()
print(f"Total OEM candidate rows: {len(rows)}")
for cve_id, title, vendor, product, raw_json in rows:
    raw = json.loads(raw_json) if raw_json else {}
    print(f"CVE: {cve_id} | DB Vendor: {vendor} | DB Product: {product} | RAW Vendor: {raw.get('affected_vendor')} | RAW Product: {raw.get('affected_application')}")
