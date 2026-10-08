import urllib.request
import re
import concurrent.futures

# Read the original missing ones from cve_scores.md
with open("cve_scores.md", "r") as f:
    lines = f.readlines()

missing_cves = []
valid_cves = {}
for line in lines[2:]:  
    parts = line.strip().split("|")
    if len(parts) >= 3:
        cve = parts[1].strip()
        score = parts[2].strip()
        if score == "N/A" or score == "Timeout" or "Error" in score:
            missing_cves.append(cve)
        else:
            valid_cves[cve] = score

def fetch_cve_feedly(cve_id):
    url = f"https://feedly.com/cve/{cve_id}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode()
            
            # Find CVSS score in Feedly HTML
            # e.g. <span ...>CVSS <!-- -->5.5</span>
            match = re.search(r'CVSS\s*(?:<!--\s*-->\s*)?([\d\.]+)', html)
            if match:
                return cve_id, match.group(1)
            
            # Or "CVSS base score of 5.5"
            match = re.search(r'CVSS base score of ([\d\.]+)', html)
            if match:
                return cve_id, match.group(1)
                
            return cve_id, "N/A"
    except Exception as e:
        return cve_id, "Timeout"

feedly_results = {}
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    future_to_cve = {executor.submit(fetch_cve_feedly, cve): cve for cve in missing_cves}
    for future in concurrent.futures.as_completed(future_to_cve):
        cve, score = future.result()
        feedly_results[cve] = score
        print(f"Feedly {cve}: {score}")

original_cve_list = [line.strip().split("|")[1].strip() for line in lines[2:] if len(line.strip().split("|")) >= 3]

with open("cve_scores_feedly.md", "w") as f:
    f.write("| CVE ID | Score |\n")
    f.write("|---|---|\n")
    for cve in original_cve_list:
        if cve in valid_cves:
            score = valid_cves[cve]
        elif cve in feedly_results:
            score = feedly_results[cve]
        else:
            score = "N/A"
        f.write(f"| {cve} | {score} |\n")
