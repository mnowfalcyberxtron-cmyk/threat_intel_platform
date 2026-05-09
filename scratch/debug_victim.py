
import sqlite3
import os

db_path = "data/threat_intel.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- Messer Griesheim Check ---")
cursor.execute("SELECT * FROM ransomware_victims WHERE victim_name LIKE '%Messer Griesheim%'")
victims = cursor.fetchall()
for v in victims:
    v_dict = dict(v)
    print(v_dict)
    
    # Check join manually
    group = v_dict['group_name']
    url = v_dict['onion_url']
    print(f"Searching onion_sites for group='{group}' or url='{url}'")
    cursor.execute("""
        SELECT * FROM onion_sites 
        WHERE (url <> '' AND url = ?) 
           OR (group_name <> '' AND (? LIKE group_name || '%' OR group_name LIKE ? || '%'))
    """, (url, group, group))
    onions = cursor.fetchall()
    for o in onions:
        print(f"  Match: {dict(o)}")

conn.close()
