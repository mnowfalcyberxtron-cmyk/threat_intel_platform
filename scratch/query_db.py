
import asyncio
import sqlite3
import os

async def main():
    db_path = "data/threat_intel.db"
    if not os.path.exists(db_path):
        print(f"DB not found at {db_path}")
        return
        
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print("--- onion_sites (with screenshots) ---")
    cursor.execute("SELECT id, group_name, url, screenshot_path, last_status FROM onion_sites WHERE screenshot_path IS NOT NULL AND screenshot_path != ''")
    rows = cursor.fetchall()
    for row in rows:
        print(dict(row))
        
    print("\n--- victims for LockBit ---")
    cursor.execute("SELECT id, victim_name, group_name, onion_url, source_url FROM ransomware_victims WHERE group_name LIKE '%LockBit%' LIMIT 5")
    rows = cursor.fetchall()
    for row in rows:
        print(dict(row))
        
    print("\n--- Joins check for LockBit ---")
    cursor.execute("""
        SELECT v.id, v.victim_name, v.group_name, o.group_name as onion_group, o.screenshot_path
        FROM ransomware_victims v
        LEFT JOIN onion_sites o ON (v.onion_url = o.url OR v.group_name LIKE o.group_name)
        WHERE v.group_name LIKE '%LockBit%'
        LIMIT 5
    """)
    rows = cursor.fetchall()
    for row in rows:
        print(dict(row))
    
    conn.close()

if __name__ == "__main__":
    asyncio.run(main())
