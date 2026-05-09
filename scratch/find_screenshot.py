
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

filename = "lockbit3_70.png"
print(f"--- Searching for '{filename}' ---")
cursor.execute("SELECT id, group_name, url, screenshot_path, last_status, page_title FROM onion_sites WHERE screenshot_path LIKE ?", (f"%{filename}%",))
rows = cursor.fetchall()
for r in rows:
    print(dict(r))

conn.close()
