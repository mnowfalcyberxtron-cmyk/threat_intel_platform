
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- Top 50 victims by discovery date ---")
cursor.execute("SELECT victim_name, group_name, discovery_date FROM ransomware_victims ORDER BY discovery_date DESC LIMIT 50")
for r in cursor.fetchall():
    print(dict(r))

conn.close()
