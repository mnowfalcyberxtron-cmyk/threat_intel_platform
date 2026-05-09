import sqlite3
conn = sqlite3.connect('data/threat_intel.db')
cur = conn.cursor()
cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='onion_sites'")
print(cur.fetchone()[0])
conn.close()
