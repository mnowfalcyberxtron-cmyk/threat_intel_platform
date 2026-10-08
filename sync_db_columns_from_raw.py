import sqlite3
import json

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

# Query all advisories where raw_data vendor differs from db table vendor
cursor.execute("SELECT cve_id, vendor, product, raw_data FROM ics_advisories")
rows = cursor.fetchall()

updated = 0
for cve_id, db_vendor, db_product, raw_json in rows:
    if not raw_json:
        continue
    try:
        raw = json.loads(raw_json)
    except Exception:
        continue
        
    raw_vendor = raw.get('affected_vendor')
    raw_product = raw.get('affected_application')
    
    if raw_vendor and (raw_vendor != db_vendor or raw_product != db_product):
        cursor.execute(
            "UPDATE ics_advisories SET vendor = ?, product = ? WHERE cve_id = ?",
            (raw_vendor, raw_product, cve_id)
        )
        updated += 1

conn.commit()
print(f"Successfully synced DB vendor & product columns from raw_data for {updated} rows!")
conn.close()
