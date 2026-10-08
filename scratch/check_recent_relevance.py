import sqlite3
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    pass

conn = sqlite3.connect("data/threat_intel.db")
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Get last 5 minutes items
cur.execute("SELECT id, title, category, relevance, fetched_at, published FROM threat_feed WHERE fetched_at >= datetime('now','-5 minutes')")
rows = cur.fetchall()
print(f"Total items fetched in last 5 minutes: {len(rows)}")
for r in rows:
    print(f"- ID {r['id']}: {r['title'][:50]}... | Relevance: {r['relevance']} | Category: {r['category']} | Published: {r['published']}")

conn.close()
