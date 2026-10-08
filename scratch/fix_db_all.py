"""
One-shot DB cleanup (handles locked DB with retry):
1. Strip "Affected:" / "Fixed:" prefixes from all existing enriched rows.
2. Recompute xtron_score for enriched rows.
3. Reset NVD-completed rows to 'pending' so they re-enrich with CVSS 3.1 priority.
"""
import sqlite3, re, sys, time
sys.stdout.reconfigure(encoding='utf-8')

DB_PATH = 'data/threat_intel.db'

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.row_factory = sqlite3.Row
    return conn

PFX = re.compile(r'^(?:affected|fixed)\s*:\s*', re.IGNORECASE)

def calc_score(severity, poc_bool_str):
    sev = str(severity or "").strip().lower()
    poc = str(poc_bool_str or "").strip().lower() == "true"
    sev_score = 65 if sev=="critical" else (60 if sev=="high" else (50 if sev=="medium" else (35 if sev=="low" else 0)))
    return sev_score + (10 if poc else 0)

conn = get_conn()
cur = conn.cursor()

# 1. Strip "Affected:" / "Fixed:" prefixes
print("Step 1: Stripping Affected:/Fixed: prefixes...")
cur.execute("SELECT id, affected_version, fixed_version FROM ics_advisories WHERE ai_enriched=1")
rows = cur.fetchall()
updates = []
for r in rows:
    aff = PFX.sub("", r["affected_version"] or "").strip()
    fix = PFX.sub("", r["fixed_version"] or "").strip()
    if aff != (r["affected_version"] or "") or fix != (r["fixed_version"] or ""):
        updates.append((aff, fix, r["id"]))

print(f"  Rows to update: {len(updates)}")
for batch_start in range(0, len(updates), 50):
    batch = updates[batch_start:batch_start+50]
    cur.executemany("UPDATE ics_advisories SET affected_version=?, fixed_version=? WHERE id=?", batch)
    conn.commit()
    time.sleep(0.05)
print(f"  Done: stripped prefixes from {len(updates)} rows.")

# 2. Recompute xtron_score for enriched rows
print("\nStep 2: Recomputing xtron_score...")
cur.execute("SELECT id, severity, poc_available_bool, xtron_score FROM ics_advisories WHERE ai_enriched=1")
rows = cur.fetchall()
score_fixes = []
for r in rows:
    expected = calc_score(r["severity"], r["poc_available_bool"])
    if r["xtron_score"] != expected:
        score_fixes.append((expected, r["id"]))

print(f"  Rows with wrong xtron_score: {len(score_fixes)}")
for batch_start in range(0, len(score_fixes), 100):
    batch = score_fixes[batch_start:batch_start+100]
    cur.executemany("UPDATE ics_advisories SET xtron_score=? WHERE id=?", batch)
    conn.commit()
    time.sleep(0.05)
print(f"  Done: recomputed {len(score_fixes)} xtron_score values.")

# 3. Reset NVD-completed rows to 'pending' so they re-run with CVSS 3.1 priority
print("\nStep 3: Resetting NVD-completed rows to pending for CVSS 3.1 re-enrichment...")
cur.execute("SELECT COUNT(*) FROM ics_advisories WHERE nvd_enrichment_status='completed'")
cnt = cur.fetchone()[0]
print(f"  Rows to reset: {cnt}")
cur.execute("UPDATE ics_advisories SET nvd_enrichment_status='pending' WHERE nvd_enrichment_status='completed'")
conn.commit()
print(f"  Done: reset {cnt} rows to 'pending'.")

conn.close()
print("\nAll done. Restart the server to start re-enrichment with CVSS 3.1 priority.")
