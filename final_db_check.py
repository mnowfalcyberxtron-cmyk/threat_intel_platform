import sqlite3
conn = sqlite3.connect('data/threat_intel.db')
cur = conn.cursor()
cur.execute("SELECT group_name, url FROM onion_sites WHERE group_name LIKE '%lamashtu%' OR group_name LIKE '%netrunner%'")
print(cur.fetchall())
conn.close()
