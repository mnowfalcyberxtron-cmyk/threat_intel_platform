
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- Recent Logs ---")
cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 30")
for row in cursor.fetchall():
    print(f"[{row['timestamp']}] {row['level']} {row['source']}: {row['message']}")

print("\n--- Sources Status ---")
cursor.execute("SELECT name, status, last_fetched, records_fetched, error_msg FROM sources")
for row in cursor.fetchall():
    print(dict(row))

conn.close()
