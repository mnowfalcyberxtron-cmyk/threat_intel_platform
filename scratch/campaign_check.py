import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cur = conn.cursor()

# Get campaign stats
cur.execute("SELECT campaign, COUNT(*) FROM iocs WHERE campaign IS NOT NULL AND campaign != '' GROUP BY campaign ORDER BY COUNT(*) DESC")
rows = cur.fetchall()
print(f"Total rows with campaign: {sum(r[1] for r in rows)}")
print("Campaigns:")
for r in rows[:20]:
    print(f"  {r[0]}: {r[1]} IOCs")

# Let's check a sample of these campaign IOCs
if rows:
    top_campaign = rows[0][0]
    print(f"\nSample IOCs for campaign '{top_campaign}':")
    cur.execute("SELECT ioc, ioc_type, threat_actor, malware FROM iocs WHERE campaign = ? LIMIT 5", (top_campaign,))
    for ioc in cur.fetchall():
        print(f"  {ioc[0]} ({ioc[1]}) | Actor: {ioc[2]} | Malware: {ioc[3]}")

conn.close()
