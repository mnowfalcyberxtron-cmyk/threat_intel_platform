import sqlite3
conn = sqlite3.connect('data/threat_intel.db')
cur = conn.cursor()
cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='ics_advisories'")
row = cur.fetchone()
print(row[0] if row else 'NOT FOUND')
conn.close()
