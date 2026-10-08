import sqlite3
import json

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

# 1. Update CVE-2026-3014 to Milestone Systems & XProtect Management Server
cursor.execute("SELECT raw_data FROM ics_advisories WHERE cve_id = 'CVE-2026-3014'")
row = cursor.fetchone()
if row:
    raw_data = json.loads(row[0])
    raw_data['affected_vendor'] = 'Milestone Systems'
    raw_data['affected_application'] = 'XProtect Management Server'
    raw_data['vendor_hq'] = 'Denmark' # Milestone Systems HQ is Denmark
    
    cursor.execute("""
        UPDATE ics_advisories 
        SET vendor = 'Milestone Systems', 
            product = 'XProtect Management Server',
            vendor_hq = 'Denmark',
            raw_data = ?
        WHERE cve_id = 'CVE-2026-3014'
    """, (json.dumps(raw_data),))
    print("Updated CVE-2026-3014 to Milestone Systems / XProtect Management Server (HQ Denmark)")

conn.commit()
conn.close()
