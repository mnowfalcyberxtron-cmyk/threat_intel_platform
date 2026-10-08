import sqlite3

conn = sqlite3.connect('data/threat_intel.db')
c = conn.cursor()

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

# Test ALL months across multiple years
years = [2024, 2025, 2026]
month_names = {1:'Jan',2:'Feb',3:'Mar',4:'Apr',5:'May',6:'Jun',
               7:'Jul',8:'Aug',9:'Sep',10:'Oct',11:'Nov',12:'Dec'}

print("=" * 70)
print(f"{'Year':<6} {'Month':<6} {'Total':>7}  {'Bad (wrong month)':>18}  {'Status'}")
print("=" * 70)

all_ok = True
for year in years:
    for month in range(1, 13):
        # Count rows
        total = c.execute(f"""
            SELECT COUNT(*) FROM ics_advisories
            WHERE ({rel_year_expr} = {year}) AND ({rel_month_expr} = {month})
        """).fetchone()[0]

        if total == 0:
            continue

        # Count bad rows — where actual release_date does NOT match the month filter
        bad = c.execute(f"""
            SELECT COUNT(*) FROM ics_advisories
            WHERE ({rel_year_expr} = {year}) AND ({rel_month_expr} = {month})
            AND (
                release_month != {month}
                OR release_year != {year}
            )
        """).fetchone()[0]

        status = "OK" if bad == 0 else f"BROKEN ({bad} wrong rows)"
        if bad > 0:
            all_ok = False
            # Show the bad ones
            sample = c.execute(f"""
                SELECT release_date, release_month, release_year FROM ics_advisories
                WHERE ({rel_year_expr} = {year}) AND ({rel_month_expr} = {month})
                AND (release_month != {month} OR release_year != {year})
                LIMIT 3
            """).fetchall()
            print(f"{year:<6} {month_names[month]:<6} {total:>7}  {bad:>18}  {status}")
            print(f"         Sample bad rows: {sample}")
        else:
            print(f"{year:<6} {month_names[month]:<6} {total:>7}  {bad:>18}  {status}")

print("=" * 70)
print("ALL MONTHS OK!" if all_ok else "SOME MONTHS HAVE ISSUES!")
