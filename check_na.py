import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

cursor.execute("SELECT cve_id, vendor, product, severity FROM ics_advisories WHERE vendor='N/A' OR vendor='' OR vendor IS NULL")
rows = cursor.fetchall()
print(f"Rows with missing vendor: {len(rows)}")
print("First 5:", rows[:5])

cursor.execute("SELECT cve_id, vendor, product, severity FROM ics_advisories LIMIT 5")
print("First 5 in DB:", cursor.fetchall())
