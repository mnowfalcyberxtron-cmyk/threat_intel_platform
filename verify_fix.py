import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

print("=== Current State After Fix ===\n")

cursor.execute("SELECT COUNT(*) FROM ics_advisories")
print(f"Total rows: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE release_year=2026 AND release_month=7")
print(f"July 2026 (by release_year+release_month): {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE xtron_score IS NOT NULL")
print(f"Rows with xtron_score: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE patch_available_bool != '' AND patch_available_bool IS NOT NULL")
print(f"Rows with patch_available_bool: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched = 0 AND release_year=2026 AND release_month>=7")
print(f"July 2026+ rows queued for AI (ai_enriched=0): {cursor.fetchone()[0]}")

print("\n=== Sample July 2026 rows ===")
cursor.execute("""
    SELECT cve_id, release_date, release_year, release_month, severity, ai_enriched, 
           xtron_score, patch_available_bool, poc_available_bool, impact
    FROM ics_advisories WHERE release_year=2026 AND release_month=7 LIMIT 5
""")
for r in cursor.fetchall():
    print(f"  CVE:{r[0]} | date:{r[1]} | yr:{r[2]} | mo:{r[3]} | sev:{r[4]} | ai:{r[5]} | xtron:{r[6]} | patch_bool:{r[7]} | poc_bool:{r[8]} | impact:{str(r[9])[:50]}")

print("\n=== ICS Meta count by month ===")
cursor.execute("""
    SELECT release_year, release_month, COUNT(*) as cnt
    FROM ics_advisories
    GROUP BY release_year, release_month
    ORDER BY release_year DESC, release_month DESC
    LIMIT 12
""")
for r in cursor.fetchall():
    print(f"  {r[0]}-{str(r[1]).zfill(2)}: {r[2]}")

print("\n=== get_ics_meta simulation for July 2026 ===")
cursor.execute("""
    SELECT DISTINCT release_date FROM ics_advisories 
    WHERE release_year=2026 AND release_month=7 LIMIT 5
""")
dates = [r[0] for r in cursor.fetchall()]
print(f"  Sample release_dates: {dates}")

print("\n=== Check _repopulateIcsDropdowns source ===")
# The meta endpoint uses get_ics_meta from db which queries
cursor.execute("SELECT DISTINCT release_year, release_month FROM ics_advisories ORDER BY release_year DESC, release_month DESC LIMIT 15")
print("DB distinct year/months:")
for r in cursor.fetchall():
    print(f"  {r[0]}-{str(r[1]).zfill(2) if r[1] else 'NULL'}")

conn.close()
