"""
One-shot DB cleanup:
1. Strip "Affected:" / "Fixed:" prefixes from all existing enriched rows.
2. Recompute xtron_score for enriched rows where severity/poc_bool mismatch.
"""
import sqlite3, re, sys
sys.stdout.reconfigure(encoding='utf-8')

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

PFX = re.compile(r'^(?:affected|fixed)\s*:\s*', re.IGNORECASE)

# 1. Strip prefixes
cur.execute("SELECT id, affected_version, fixed_version FROM ics_advisories WHERE ai_enriched=1")
rows = cur.fetchall()
updates = []
for r in rows:
    aff = PFX.sub("", r["affected_version"] or "").strip()
    fix = PFX.sub("", r["fixed_version"]    or "").strip()
    if aff != (r["affected_version"] or "") or fix != (r["fixed_version"] or ""):
        updates.append((aff, fix, r["id"]))

print(f"Rows with prefix to strip: {len(updates)}")
for (aff, fix, rid) in updates:
    cur.execute("UPDATE ics_advisories SET affected_version=?, fixed_version=? WHERE id=?", (aff, fix, rid))

conn.commit()
print(f"Stripped prefixes from {len(updates)} rows.")

# 2. Recompute xtron_score for enriched rows to ensure correctness
def calc_score(severity, poc_bool_str):
    sev = str(severity or "").strip().lower()
    poc = str(poc_bool_str or "").strip().lower() == "true"
    sev_score = 65 if sev=="critical" else (60 if sev=="high" else (50 if sev=="medium" else (35 if sev=="low" else 0)))
    return sev_score + (10 if poc else 0)

cur.execute("SELECT id, severity, poc_available_bool, xtron_score FROM ics_advisories WHERE ai_enriched=1")
rows = cur.fetchall()
score_fixes = []
for r in rows:
    expected = calc_score(r["severity"], r["poc_available_bool"])
    if r["xtron_score"] != expected:
        score_fixes.append((expected, r["id"]))

print(f"Rows with wrong xtron_score: {len(score_fixes)}")
for (score, rid) in score_fixes:
    cur.execute("UPDATE ics_advisories SET xtron_score=? WHERE id=?", (score, rid))

conn.commit()
print(f"Recomputed xtron_score for {len(score_fixes)} rows.")
conn.close()
print("Done.")
