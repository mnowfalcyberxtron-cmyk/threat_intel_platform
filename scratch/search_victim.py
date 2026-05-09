
import sqlite3
import os
import sys

# Set output encoding to UTF-8
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

query = "Griesheim"
print(f"--- Searching for '{query}' ---")
cursor.execute("SELECT * FROM ransomware_victims WHERE victim_name LIKE ?", (f"%{query}%",))
victims = cursor.fetchall()
for v in victims:
    print(dict(v))

conn.close()
