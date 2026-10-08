import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

print('=== Current DB State (Post VSCode changes) ===')
cursor.execute('SELECT COUNT(*) FROM ics_advisories')
print(f'Total rows: {cursor.fetchone()[0]}')

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched=1")
print(f'ai_enriched=1: {cursor.fetchone()[0]}')

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE (ai_enriched=0 OR ai_enriched IS NULL)")
print(f'ai_enriched=0/null (queued): {cursor.fetchone()[0]}')

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE xtron_score IS NOT NULL")
print(f'xtron_score filled: {cursor.fetchone()[0]}')

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE patch_available_bool != '' AND patch_available_bool IS NOT NULL")
print(f'patch_available_bool filled: {cursor.fetchone()[0]}')

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE (cve_pub_year > 2026 OR (cve_pub_year = 2026 AND cve_pub_month >= 7)) AND (ai_enriched=0 OR ai_enriched IS NULL)")
print(f'Ready for AI (cve_pub 2026-07+, ai_enriched=0): {cursor.fetchone()[0]}')

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE release_year=2026 AND release_month=7")
print(f'July 2026 advisory count (release month): {cursor.fetchone()[0]}')

cursor.execute("SELECT cve_id, ai_enriched, xtron_score, patch_available_bool, poc_available_bool, impact FROM ics_advisories WHERE release_year=2026 AND release_month=7 LIMIT 5")
print('\nSample July 2026:')
for r in cursor.fetchall():
    cve_id, ai, xtron, patch, poc, impact = r
    print(f'  {cve_id} | ai:{ai} | xtron:{xtron} | patch:{patch} | poc:{poc} | impact:{str(impact)[:60]}')

# Check if impact has any proper AI narratives  
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE impact LIKE 'A successful exploit%'")
print(f'\nProper AI narratives (impact starts with A successful exploit): {cursor.fetchone()[0]}')

# What the ics_ai_enrichment queue looks like now
cursor.execute("""
    SELECT cve_id, cve_pub_year, cve_pub_month, release_year, release_month 
    FROM ics_advisories 
    WHERE (cve_pub_year > 2026 OR (cve_pub_year = 2026 AND cve_pub_month >= 7)) 
      AND (ai_enriched=0 OR ai_enriched IS NULL)
    LIMIT 5
""")
print('\nSample rows queued for AI:')
for r in cursor.fetchall():
    print(f'  {r}')

conn.close()
