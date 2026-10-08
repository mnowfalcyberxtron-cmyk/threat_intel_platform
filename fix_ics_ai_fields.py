"""
Fix script: Reset fake-enriched ICS advisory rows so the AI loop processes them properly.

The issue: In a previous session, ai_enriched=1 was set for all rows without running AI.
As a result, 13,622 rows have ai_enriched=1 but NO xtron_score, patch_available_bool, or
proper impact narrative. The AI loop skips them because ai_enriched=1.

Fix:
 1. Reset ai_enriched=0 for all rows where xtron_score IS NULL (fake-enriched rows)
 2. Compute xtron_score on-the-fly for rows that don't need AI (pre-2026-07-01)
 3. Update impact column to readable CWE text for rows without AI narrative
"""
import sqlite3
import re

conn = sqlite3.connect('data/threat_intel.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# CWE -> readable impact lookup
CWE_IMPACT = {
    "CWE-22":  "Path Traversal",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection",
    "CWE-20":  "Improper Input Validation",
    "CWE-23":  "Relative Path Traversal",
    "CWE-35":  "Path Traversal",
    "CWE-59":  "Link Following",
    "CWE-77":  "Command Injection",
    "CWE-88":  "Argument Injection",
    "CWE-91":  "XML Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Stack Buffer Overflow",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure",
    "CWE-255": "Credentials Management Error",
    "CWE-256": "Cleartext Storage of Password",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-294": "Authentication Bypass by Capture-replay",
    "CWE-295": "Certificate Validation Failure",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption (DoS)",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "XML External Entity (XXE) Injection",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def cwe_to_impact(cwe_str):
    if not cwe_str or str(cwe_str).strip().lower() in ('', 'n/a', 'unknown', 'none'):
        return None  # Return None if CWE empty
    impacts = []
    for cwe in re.split(r'[,;]\s*', str(cwe_str).strip()):
        cwe = cwe.strip()
        label = CWE_IMPACT.get(cwe)
        if label and label not in impacts:
            impacts.append(label)
    return ', '.join(impacts) if impacts else None


def calc_xtron(severity, poc_bool):
    sev = str(severity or '').strip().lower()
    sev_pts = 65 if sev == 'critical' else (60 if sev == 'high' else (50 if sev == 'medium' else (35 if sev == 'low' else 0)))
    return sev_pts + (10 if poc_bool else 0)


print("Step 1: Checking current state...")
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched=1 AND xtron_score IS NULL")
fake_count = cursor.fetchone()[0]
print(f"  Fake-enriched rows (ai_enriched=1 but no xtron_score): {fake_count}")

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE xtron_score IS NOT NULL")
real_count = cursor.fetchone()[0]
print(f"  Real AI enriched rows (xtron_score filled): {real_count}")

cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE release_year=2026 AND release_month>=7")
july_count = cursor.fetchone()[0]
print(f"  July 2026+ advisory rows: {july_count}")

print("\nStep 2: Computing xtron_score and patch/poc booleans for all rows without xtron_score...")
cursor.execute("""
    SELECT id, severity, kev_flag, patch_availability, poc_availability, cwe, impact
    FROM ics_advisories
    WHERE xtron_score IS NULL
""")
rows = cursor.fetchall()
print(f"  Rows to process: {len(rows)}")

updated = 0
for row in rows:
    row_id = row['id']
    severity = row['severity'] or ''
    kev_flag = str(row['kev_flag'] or '').strip().lower()
    patch_avail = str(row['patch_availability'] or '').strip().lower()
    poc_avail = str(row['poc_availability'] or '').strip().lower()
    cwe = row['cwe'] or ''
    current_impact = row['impact'] or ''
    
    # Determine patch bool
    patch_bool = patch_avail in ('yes', 'true', '1')
    
    # Determine poc bool  
    poc_bool = poc_avail in ('yes', 'true', '1') or kev_flag in ('yes', 'true', '1', 'kev')
    
    # Calculate xtron score
    xtron = calc_xtron(severity, poc_bool)
    
    # Build impact text from CWE if current impact is raw/generic CWE shorthand or empty
    new_impact = current_impact
    # If current impact is just a CWE shorthand (from _cwe_to_impact, which gives abbreviated names),
    # replace with better text from the expanded CWE map
    if cwe and (not current_impact or current_impact in ('Unknown', 'unknown')):
        better = cwe_to_impact(cwe)
        if better:
            new_impact = better
    
    cursor.execute("""
        UPDATE ics_advisories SET
            patch_available_bool = ?,
            poc_available_bool = ?,
            xtron_score = ?,
            ai_enriched = 0,
            impact = CASE WHEN ? != '' THEN ? ELSE impact END
        WHERE id = ?
    """, (
        'True' if patch_bool else 'False',
        'True' if poc_bool else 'False',
        xtron,
        new_impact, new_impact,
        row_id
    ))
    updated += 1
    if updated % 1000 == 0:
        conn.commit()
        print(f"  Processed {updated}...")

conn.commit()
print(f"  Updated {updated} rows with xtron_score + patch/poc booleans, and ai_enriched=0")

print("\nStep 3: Reset ai_enriched=0 for rows with impact showing raw CWE short names (not proper AI narrative)...")
# Rows that were bulk-marked ai_enriched=1 without actual AI - these have no impact narrative
# The AI loop needs ai_enriched=0 to re-process them
# But ONLY rows qualifying for AI (recent advisories) need to be reset
cursor.execute("""
    UPDATE ics_advisories SET ai_enriched = 0
    WHERE ai_enriched = 1 
    AND xtron_score IS NOT NULL
    AND (impact NOT LIKE 'A successful exploit%')
    AND release_year >= 2026 AND release_month >= 7
""")
reset_count = cursor.rowcount
conn.commit()
print(f"  Reset ai_enriched=0 for {reset_count} July 2026+ rows (will be re-queued for AI processing)")

print("\nStep 4: Verification...")
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE xtron_score IS NULL")
print(f"  Rows with no xtron_score: {cursor.fetchone()[0]}")
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched=0 AND release_year=2026 AND release_month>=7")
print(f"  July 2026+ rows queued for AI (ai_enriched=0): {cursor.fetchone()[0]}")
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE ai_enriched=1")
print(f"  Rows with ai_enriched=1 (fully processed): {cursor.fetchone()[0]}")
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE patch_available_bool != '' AND patch_available_bool IS NOT NULL")
print(f"  Rows with patch_available_bool filled: {cursor.fetchone()[0]}")
cursor.execute("SELECT COUNT(*) FROM ics_advisories WHERE impact LIKE 'A successful exploit%'")
print(f"  Rows with proper AI impact narrative: {cursor.fetchone()[0]}")

# Show sample of what July rows look like now
cursor.execute("""
    SELECT cve_id, severity, ai_enriched, xtron_score, patch_available_bool, poc_available_bool, impact
    FROM ics_advisories WHERE release_year=2026 AND release_month=7 LIMIT 5
""")
print("\nSample July 2026 rows:")
for r in cursor.fetchall():
    print(f"  CVE:{r[0]} | sev:{r[1]} | ai:{r[2]} | xtron:{r[3]} | patch:{r[4]} | poc:{r[5]} | impact:{str(r[6])[:60]}")

conn.close()
print("\nDone!")
