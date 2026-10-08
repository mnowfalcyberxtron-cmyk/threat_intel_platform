import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

query = """
SELECT cve_id, ics_number, vendor, product, title 
FROM ics_advisories 
WHERE raw_data LIKE '%Milestone%' OR raw_data LIKE '%Fortinet%' OR title LIKE '%Milestone%' OR title LIKE '%Fortinet%'
"""
cursor.execute(query)
rows = cursor.fetchall()
print(f"Total matching OEM rows: {len(rows)}")
for r in rows:
    print(r)
