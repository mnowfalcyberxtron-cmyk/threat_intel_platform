
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

for table in ["iocs", "ransomware_victims"]:
    print(f"--- Schema for {table} ---")
    cursor.execute(f"PRAGMA table_info({table})")
    for r in cursor.fetchall():
        print(dict(r))

conn.close()
