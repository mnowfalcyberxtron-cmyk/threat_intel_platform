
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- LockBit Onion Sites ---")
cursor.execute("SELECT group_name, url, screenshot_path FROM onion_sites WHERE group_name LIKE '%lockbit%'")
for r in cursor.fetchall():
    print(dict(r))

conn.close()
