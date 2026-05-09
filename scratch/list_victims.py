
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- Search for Speaker ---")
cursor.execute("SELECT * FROM ransomware_victims WHERE victim_name LIKE '%Speaker%'")
victims = cursor.fetchall()
for v in victims:
    print(dict(v))

print("\n--- All victims (first 10) ---")
cursor.execute("SELECT victim_name, group_name FROM ransomware_victims LIMIT 10")
for v in cursor.fetchall():
    print(dict(v))

conn.close()
