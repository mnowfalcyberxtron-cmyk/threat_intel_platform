import sqlite3
import os

DB_PATHS = [
    "threat_intel.db",
    "tip.db",
    "data.db",
    "database/threat_intel.db",
    "database/threatintel.db"
]

for path in DB_PATHS:
    if os.path.exists(path):
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [t[0] for t in cursor.fetchall()]
            if "ics_advisories" in tables:
                print(f"Found ics_advisories in {path}")
                cursor.execute("SELECT id, ics_number, cve_id FROM ics_advisories WHERE cve_id != 'N/A' AND cve_id != ''")
                rows = cursor.fetchall()
                print(f"Total rows with CVEs: {len(rows)}")
                for row in rows[:5]:
                    print(row)
        except Exception as e:
            pass
