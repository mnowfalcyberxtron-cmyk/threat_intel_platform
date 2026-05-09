import sqlite3
import os

db_path = "data/threat_intel.db"
if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
else:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print("Checking onion_sites for 'lamashtu'...")
    cursor.execute("SELECT * FROM onion_sites WHERE group_name LIKE '%lamashtu%' OR url LIKE '%lamashtu%'")
    rows = cursor.fetchall()
    for r in rows:
        print(dict(r))
    
    print("\nChecking ransomware_victims for 'lamashtu'...")
    cursor.execute("SELECT * FROM ransomware_victims WHERE group_name LIKE '%lamashtu%' OR victim_name LIKE '%lamashtu%'")
    rows = cursor.fetchall()
    for r in rows:
        print(dict(r))
    
    conn.close()
