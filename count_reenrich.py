import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE cve_published_date >= '2026-07-01'")
print('Qualify (cve_pub >= 2026-07-01):', cursor.fetchone()[0])

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE release_year=2026 AND release_month>=7")
print('By release_year/month (2026-07+):', cursor.fetchone()[0])

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE xtron_score IS NOT NULL")
print('xtron_score filled:', cursor.fetchone()[0])

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched=1 AND xtron_score IS NULL")
print('AI fake-enriched (no xtron_score):', cursor.fetchone()[0])

# Key insight: how many rows need re-enrichment?
# We'll reset ai_enriched=0 for those with no xtron_score so the loop picks them up
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched=1 AND xtron_score IS NULL AND cve_published_date >= '2026-07-01'")
print('Fake-enriched + qualify for AI:', cursor.fetchone()[0])

# Also check impact content
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE impact LIKE 'A successful exploit%'")
print('Proper AI impact narratives:', cursor.fetchone()[0])

conn.close()
