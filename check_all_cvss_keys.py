import sqlite3
import json

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute("SELECT normalized_data FROM ics_advisories")
rows = cursor.fetchall()
keys_found = set()
for row in rows:
    try:
        data = json.loads(row['normalized_data'])
        for k in data.keys():
            keys_found.add(k)
    except Exception as e:
        pass

print("Keys found in normalized_data:")
cvss_keys = [k for k in keys_found if 'cvss' in k.lower()]
print(cvss_keys)
