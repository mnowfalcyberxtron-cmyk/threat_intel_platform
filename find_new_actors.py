import sys
import io
# Fix console encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import sqlite3
conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Find groups in victims that aren't in onion_sites
cur.execute("""
    SELECT DISTINCT group_name 
    FROM ransomware_victims 
    WHERE group_name NOT IN (SELECT group_name FROM onion_sites) 
    AND group_name NOT IN ('unknown', 'Unknown', '')
""")
new_groups = [r['group_name'] for r in cur.fetchall()]
print(f"Untracked groups count: {len(new_groups)}")

# For each new group, check if we have a URL anywhere and ADD it
added_count = 0
for g in new_groups:
    url = None
    cur.execute("SELECT ioc FROM iocs WHERE threat_actor=? AND ioc LIKE '%.onion%' LIMIT 1", (g,))
    row = cur.fetchone()
    if row: url = row[0]
    else:
        cur.execute("SELECT source_url FROM ransomware_victims WHERE group_name=? AND source_url LIKE '%.onion%' LIMIT 1", (g,))
        row = cur.fetchone()
        if row: url = row[0]
        else:
            cur.execute("SELECT onion_url FROM ransomware_victims WHERE group_name=? AND onion_url LIKE '%.onion%' LIMIT 1", (g,))
            row = cur.fetchone()
            if row: url = row[0]

    if url:
        try:
            cur.execute(
                "INSERT OR IGNORE INTO onion_sites (group_name, url, description, active) VALUES (?,?,?,1)",
                (g, url, "Automatically discovered")
            )
            if cur.rowcount > 0:
                print(f"Propagated: {g} -> {url}")
                added_count += 1
        except: pass

conn.commit()
print(f"Total new actors propagated to monitor: {added_count}")
conn.close()
