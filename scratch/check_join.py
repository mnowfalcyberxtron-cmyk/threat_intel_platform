
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- Testing Join for lockbit3 ---")
cursor.execute("""
    SELECT v.victim_name, v.group_name, o.group_name as onion_group, o.screenshot_path
    FROM ransomware_victims v
    LEFT JOIN onion_sites o ON 
        (v.onion_url <> '' AND v.onion_url = o.url)
        OR (v.group_name <> '' AND (
            v.group_name LIKE o.group_name || '%'
            OR o.group_name LIKE v.group_name || '%'
        ))
    WHERE v.group_name LIKE '%lockbit%'
    LIMIT 20
""")
for r in cursor.fetchall():
    print(dict(r))

conn.close()
