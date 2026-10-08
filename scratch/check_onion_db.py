import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

cur.execute("SELECT group_name, url, last_status, last_checked FROM onion_sites WHERE last_status = '200' LIMIT 5")
rows = cur.fetchall()

print(f"Online sites ({len(rows)} found):")
for row in rows:
    print(dict(row))

conn.close()
