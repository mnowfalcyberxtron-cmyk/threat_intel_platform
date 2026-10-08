import json
import urllib.request
import concurrent.futures
import time
import re
import urllib.error

# Read the existing markdown table
with open("cve_scores.md", "r") as f:
    lines = f.readlines()

missing_cves = []
valid_cves = {}
for line in lines[2:]:  # skip header
    parts = line.strip().split("|")
    if len(parts) >= 3:
        cve = parts[1].strip()
        score = parts[2].strip()
        if score == "N/A" or score == "Timeout" or "Error" in score:
            missing_cves.append(cve)
        else:
            valid_cves[cve] = score

def fetch_cve_nvd(cve_id):
    # Try NVD API first
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return cve_id, "N/A"
            metrics = vulns[0].get("cve", {}).get("metrics", {})
            max_score = None
            
            for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    for m in metrics[version]:
                        score = m.get("cvssData", {}).get("baseScore")
                        if score is not None:
                            try:
                                f_score = float(score)
                                if max_score is None or f_score > max_score:
                                    max_score = f_score
                            except ValueError:
                                pass
            if max_score is not None:
                return cve_id, str(max_score)
            
            return cve_id, "N/A"
    except urllib.error.HTTPError as e:
        if e.code == 403 or e.code == 429: # Rate limit
            return cve_id, "RateLimit"
        return cve_id, f"Error: {e.code}"
    except Exception as e:
        return cve_id, "Timeout"

def fetch_cve_mitre(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
            adp = data.get("containers", {}).get("adp", [])
            for a in adp:
                if "metrics" in a:
                    metrics.extend(a["metrics"])

            max_score = None
            for m in metrics:
                score = None
                if "cvssV3_1" in m:
                    score = m["cvssV3_1"].get("baseScore")
                elif "cvssV4_0" in m:
                    score = m["cvssV4_0"].get("baseScore")
                
                if score is not None:
                    try:
                        f_score = float(score)
                        if max_score is None or f_score > max_score:
                            max_score = f_score
                    except ValueError:
                        pass
            
            return cve_id, str(max_score) if max_score else "N/A"
    except Exception as e:
        return cve_id, "Timeout"

# We will retry with Mitre first (in case it was a timeout), then fallback to NVD with a delay
results = {}
for cve in missing_cves:
    # try mitre first
    _, mitre_score = fetch_cve_mitre(cve)
    if mitre_score not in ("N/A", "Timeout"):
        results[cve] = mitre_score
        print(f"{cve}: {mitre_score} (Mitre Retry)")
    else:
        # try NVD
        _, nvd_score = fetch_cve_nvd(cve)
        results[cve] = nvd_score
        print(f"{cve}: {nvd_score} (NVD Fallback)")
        time.sleep(1)  # avoid NVD rate limit of 5 req/sec

# Keep the original order
original_cve_list = [line.strip().split("|")[1].strip() for line in lines[2:] if len(line.strip().split("|")) >= 3]

with open("cve_scores_final.md", "w") as f:
    f.write("| CVE ID | Score |\n")
    f.write("|---|---|\n")
    for cve in original_cve_list:
        if cve in valid_cves:
            score = valid_cves[cve]
        elif cve in results:
            score = results[cve]
        else:
            score = "N/A"
        f.write(f"| {cve} | {score} |\n")
