import sqlite3
import os
import json
import re
import urllib.request
import zipfile
import time

DB_PATH = "data/threat_intel.db"
ZIP_FILE = "cvelistV5.zip"

def get_cve_zip_path(cve_id):
    match = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
    if not match: return None
    year, num = match.groups()
    if len(num) <= 3:
        thousands = "0xxx"
    else:
        thousands = num[:-3] + "xxx"
    return f"cvelistV5-main/cves/{year}/{thousands}/{cve_id}.json"

def extract_cvss(data):
    containers = data.get('containers', {})
    adps = containers.get('adp', [])
    cna = containers.get('cna', {})

    metrics = []
    for adp in adps:
        metrics.extend(adp.get('metrics', []))
    metrics.extend(cna.get('metrics', []))

    # Priority: v3.1 > v3.0 > v2.0 > v4.0 (as requested: v3 -> v2 -> v4)
    for m in metrics:
        cvss = m.get('cvssV3_1') or m.get('cvssV3_0')
        if cvss and 'baseScore' in cvss and 'baseSeverity' in cvss:
            return str(cvss['baseScore']), cvss['baseSeverity'].upper()

    for m in metrics:
        cvss = m.get('cvssV2_0')
        if cvss and 'baseScore' in cvss:
            # v2 doesn't always have baseSeverity, we might need to derive it
            sev = cvss.get('baseSeverity')
            if not sev:
                sc = float(cvss['baseScore'])
                if sc >= 7.0: sev = "HIGH"
                elif sc >= 4.0: sev = "MEDIUM"
                else: sev = "LOW"
            return str(cvss['baseScore']), sev.upper()

    for m in metrics:
        cvss = m.get('cvssV4_0')
        if cvss and 'baseScore' in cvss and 'baseSeverity' in cvss:
            return str(cvss['baseScore']), cvss['baseSeverity'].upper()
    
    return None, None

def fetch_from_web(cve_id):
    # Use circl.lu API as it's unauthenticated and easy
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            # Try v3
            cvss3 = data.get('cvss3')
            if cvss3:
                # circl might not have severity string, but let's see if we can derive it
                sc = float(cvss3)
                sev = "CRITICAL" if sc >= 9.0 else "HIGH" if sc >= 7.0 else "MEDIUM" if sc >= 4.0 else "LOW"
                return str(cvss3), sev
            # Try v2
            cvss2 = data.get('cvss')
            if cvss2:
                sc = float(cvss2)
                sev = "HIGH" if sc >= 7.0 else "MEDIUM" if sc >= 4.0 else "LOW"
                return str(cvss2), sev
    except Exception as e:
        print(f"Web fetch failed for {cve_id}: {e}")
    return None, None

def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get rows that STILL don't have cvss_score, or were not updated
    # To be safe, let's process ALL again.
    cursor.execute("SELECT id, ics_number, cve_id FROM ics_advisories WHERE cve_id != 'N/A' AND cve_id != ''")
    rows = cursor.fetchall()
    
    updates = []
    
    with zipfile.ZipFile(ZIP_FILE, 'r') as z:
        zip_files = set(z.namelist())

        for row in rows:
            row_id = row[0]
            cves = [c.strip() for c in row[2].split(",")]
            
            best_score = -1.0
            best_severity = "UNKNOWN"
            best_score_str = ""
            is_web = False

            for cve in cves:
                if not cve.startswith("CVE-"): continue
                path = get_cve_zip_path(cve)
                score, sev = None, None
                
                if path and path in zip_files:
                    try:
                        with z.open(path) as f:
                            data = json.load(f)
                            score, sev = extract_cvss(data)
                    except: pass
                else:
                    # Missing from ZIP! Try web!
                    print(f"Missing in ZIP, trying web for {cve}...")
                    score, sev = fetch_from_web(cve)
                    if score:
                        # Append marker
                        score = f"{score} (Web)"
                        is_web = True
                        time.sleep(0.5) # rate limit prevention

                if score and sev:
                    try:
                        # Handle "(Web)" suffix for float conversion
                        sc_val = float(score.replace(" (Web)", ""))
                        if sc_val > best_score:
                            best_score = sc_val
                            best_severity = sev
                            best_score_str = score
                    except:
                        pass
            
            if best_score >= 0:
                updates.append((best_score_str, best_severity, row_id))

    print(f"Found updates for {len(updates)} rows. Updating DB...")
    cursor.executemany("UPDATE ics_advisories SET cvss_score = ?, severity = ? WHERE id = ?", updates)
    conn.commit()
    conn.close()
    print("Done!")

if __name__ == "__main__":
    main()
