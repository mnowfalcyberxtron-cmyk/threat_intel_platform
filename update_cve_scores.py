import sqlite3
import os
import json
import re
import urllib.request
import zipfile
import time

DB_PATH = "data/threat_intel.db"
ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
ZIP_FILE = "cvelistV5.zip"

def download_file(url, dest):
    print(f"Downloading {url} to {dest}...")
    start = time.time()
    urllib.request.urlretrieve(url, dest)
    print(f"Downloaded in {time.time() - start:.2f} seconds.")

def get_cve_zip_path(cve_id):
    match = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
    if not match: return None
    year, num = match.groups()
    if len(num) <= 3:
        thousands = "0xxx"
    else:
        thousands = num[:-3] + "xxx"
    # Note: github zip contains a root folder, usually 'cvelistV5-main'
    return f"cvelistV5-main/cves/{year}/{thousands}/{cve_id}.json"

def extract_cvss(data):
    # Try ADP first (usually NVD or enriched), then CNA
    containers = data.get('containers', {})
    adps = containers.get('adp', [])
    cna = containers.get('cna', {})

    # Gather all metrics
    metrics = []
    for adp in adps:
        metrics.extend(adp.get('metrics', []))
    metrics.extend(cna.get('metrics', []))

    # Look for cvssV3_1 or cvssV3_0
    for m in metrics:
        cvss = m.get('cvssV3_1') or m.get('cvssV3_0')
        if cvss and 'baseScore' in cvss and 'baseSeverity' in cvss:
            return str(cvss['baseScore']), cvss['baseSeverity'].upper()
    
    return None, None

def main():
    if not os.path.exists(ZIP_FILE):
        download_file(ZIP_URL, ZIP_FILE)
    else:
        print("Zip file already exists. Using local copy.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT id, ics_number, cve_id FROM ics_advisories WHERE cve_id != 'N/A' AND cve_id != ''")
    rows = cursor.fetchall()
    print(f"Total rows to process: {len(rows)}")

    updates = []
    not_found = 0
    no_score = 0
    updated = 0

    with zipfile.ZipFile(ZIP_FILE, 'r') as z:
        # Get all files in zip to quickly check existence without throwing exceptions
        zip_files = set(z.namelist())

        for row in rows:
            row_id = row[0]
            cves = [c.strip() for c in row[2].split(",")]
            
            # If multiple CVEs, we pick the highest score
            best_score = -1.0
            best_severity = "UNKNOWN"
            best_score_str = ""

            for cve in cves:
                if not cve.startswith("CVE-"): continue
                path = get_cve_zip_path(cve)
                if path and path in zip_files:
                    try:
                        with z.open(path) as f:
                            data = json.load(f)
                            score, sev = extract_cvss(data)
                            if score and sev:
                                try:
                                    sc_val = float(score)
                                    if sc_val > best_score:
                                        best_score = sc_val
                                        best_severity = sev
                                        best_score_str = score
                                except:
                                    pass
                    except Exception as e:
                        print(f"Error reading {cve}: {e}")
                else:
                    not_found += 1
            
            if best_score >= 0:
                updates.append((best_score_str, best_severity, row_id))
                updated += 1
            else:
                no_score += 1

    print(f"Found updates for {updated} rows. Updating DB...")
    cursor.executemany("UPDATE ics_advisories SET cvss_score = ?, severity = ? WHERE id = ?", updates)
    conn.commit()
    conn.close()
    
    print(f"Finished! Updates: {updated}, Not found locally: {not_found}, No CVSS3 score found: {no_score}")

if __name__ == "__main__":
    main()
