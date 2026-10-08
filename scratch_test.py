import sqlite3
import traceback
try:
    conn = sqlite3.connect('e:/threat_intel_platform/data/threat_intel.db')
    cur = conn.execute("SELECT campaign, COUNT(*) as ioc_count, MAX(last_seen) as last_seen FROM iocs WHERE campaign != '' and campaign IS NOT NULL GROUP BY campaign ORDER BY last_seen DESC LIMIT 50")
    rows = cur.fetchall()
    print('Rows fetched:', len(rows))
    print(rows)
except Exception as e:
    print('DB Error:')
    traceback.print_exc()
