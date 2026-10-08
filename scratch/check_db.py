import sqlite3
import pathlib

db_path = pathlib.Path('data/threat_intel.db')
c = sqlite3.connect(db_path)
print("Total enriched:", c.execute("SELECT COUNT(*) FROM ics_advisories WHERE cve_published_date != ''").fetchone()[0])
print("Total rows:", c.execute("SELECT COUNT(*) FROM ics_advisories").fetchone()[0])
