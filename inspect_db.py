import sqlite3

con = sqlite3.connect('data/threat_intel.db')
con.row_factory = sqlite3.Row
cur = con.cursor()

# Ransomware.live rows with country
cur.execute("SELECT * FROM ransomware_victims WHERE source='ransomware_live' AND country!='' LIMIT 3")
rows = cur.fetchall()
print('=== RANSOM.LIVE ROWS WITH COUNTRY ===')
for r in rows:
    print(dict(r))

# Count by source with country
cur.execute("SELECT source, count(*) as cnt, SUM(CASE WHEN country!='' THEN 1 ELSE 0 END) as with_country FROM ransomware_victims GROUP BY source")
print('\n=== COUNTS ===')
for r in cur.fetchall():
    print(dict(r))

# IOC columns
cur.execute('PRAGMA table_info(iocs)')
cols = cur.fetchall()
print('\n=== IOC COLUMNS ===')
for c in cols:
    print(f'  {c[1]} ({c[2]})')

# IOCs with actor
cur.execute("SELECT ioc, ioc_type, malware, threat_actor FROM iocs WHERE threat_actor IS NOT NULL AND threat_actor != 'unknown' AND threat_actor != '' LIMIT 5")
rows = cur.fetchall()
print('\n=== IOCs WITH ACTOR ===')
for r in rows:
    print(dict(r))

# IOC actor stats
cur.execute("SELECT threat_actor, count(*) as cnt FROM iocs WHERE threat_actor IS NOT NULL AND threat_actor != '' AND threat_actor != 'unknown' GROUP BY threat_actor ORDER BY cnt DESC LIMIT 10")
print('\n=== TOP ACTORS IN IOC TABLE ===')
for r in cur.fetchall():
    print(dict(r))

con.close()
