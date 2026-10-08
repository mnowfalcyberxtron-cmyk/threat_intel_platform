import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
c = conn.cursor()

# New correct expressions - both year and month from release_date
rel_year_expr = """COALESCE(release_year, CAST(
    CASE
        WHEN substr(trim(release_date), 5, 1) = '-'
            THEN substr(trim(release_date), 1, 4)
        WHEN instr(trim(release_date), '/') > 0
            THEN substr(trim(release_date), length(trim(release_date))-3, 4)
        ELSE NULL
    END AS INTEGER))"""

rel_month_expr = """COALESCE(release_month, CAST(
    CASE
        WHEN substr(trim(release_date), 5, 1) = '-'
            THEN substr(trim(release_date), 6, 2)
        WHEN instr(trim(release_date), '/') > 0
            THEN substr(trim(release_date), 1, instr(trim(release_date), '/')-1)
        ELSE NULL
    END AS INTEGER))"""

# Count for June 2026
query = f"""
SELECT COUNT(*) as total, release_date, release_month, release_year
FROM ics_advisories
WHERE ({rel_year_expr} = 2026) AND ({rel_month_expr} = 6)
GROUP BY release_date, release_month, release_year
ORDER BY release_date
LIMIT 20
"""

res = c.execute(query).fetchall()
print("Results for release_year=2026, release_month=6:")
for r in res:
    print(r)

# Count total
total = c.execute(f"SELECT COUNT(*) FROM ics_advisories WHERE ({rel_year_expr} = 2026) AND ({rel_month_expr} = 6)").fetchone()[0]
print(f"\nTotal: {total}")

# Old broken query - for comparison
old_year = "COALESCE(cve_year, CAST(CASE WHEN UPPER(cve_id) LIKE 'CVE-%' THEN substr(cve_id, 5, 4) ELSE NULL END AS INTEGER))"
old_month = "COALESCE(release_month, CAST(CASE WHEN substr(trim(release_date), 5, 1) = '-' THEN substr(trim(release_date), 6, 2) WHEN instr(trim(release_date), '/') > 0 THEN substr(trim(release_date), 1, instr(trim(release_date), '/')-1) ELSE NULL END AS INTEGER), update_month)"
old_total = c.execute(f"SELECT COUNT(*) FROM ics_advisories WHERE ({old_year} = 2026) AND ({old_month} = 6)").fetchone()[0]
print(f"Old broken query total (for comparison): {old_total}")

# Now check if any wrong-month results slip through
bad = c.execute(f"""
    SELECT release_date FROM ics_advisories 
    WHERE ({rel_year_expr} = 2026) AND ({rel_month_expr} = 6)
    AND release_month != 6
    LIMIT 5
""").fetchall()
print(f"\nRows with wrong release_month (should be 0): {bad}")
