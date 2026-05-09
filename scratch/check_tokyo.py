
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- TokyoHosoKogyo Victim ---")
cursor.execute("SELECT * FROM ransomware_victims WHERE victim_name LIKE '%TokyoHosoKogyo%'")
for r in cursor.fetchall():
    print(dict(r))

conn.close()
