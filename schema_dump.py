import sqlite3

conn = sqlite3.connect('e:/threat_intel_platform/data/threat_intel.db')
for table in ['onion_sites', 'telegram_channels', 'ransomware_victims']:
    cur = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,))
    row = cur.fetchone()
    if row:
        print(row[0])
