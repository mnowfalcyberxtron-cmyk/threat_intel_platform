
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
print("Normalizing paths in onion_sites...")
conn.execute("UPDATE onion_sites SET screenshot_path = REPLACE(screenshot_path, '\\', '/') WHERE screenshot_path LIKE '%\\%'")
conn.commit()
print("Done.")
conn.close()
