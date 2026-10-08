import urllib.request
import json
import re

def get_cve_path(cve_id):
    # e.g. CVE-2021-31881 -> 2021, 31881 -> 31xxx
    # e.g. CVE-2015-3965 -> 2015, 3965 -> 3xxx
    # e.g. CVE-2023-6929 -> 2023, 6929 -> 6xxx
    match = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
    if not match: return None
    year, num = match.groups()
    if len(num) <= 3:
        # e.g. CVE-2023-123 -> 0xxx
        thousands = "0xxx"
    else:
        # e.g. 31881 -> 31, 3965 -> 3
        thousands = num[:-3] + "xxx"
    return f"cves/{year}/{thousands}/{cve_id}.json"

cves = ["CVE-2021-31881", "CVE-2015-3965", "CVE-2023-6929", "CVE-2021-44228"]
for c in cves:
    path = get_cve_path(c)
    url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/{path}"
    try:
        resp = urllib.request.urlopen(url)
        print(f"Success: {url}")
    except Exception as e:
        print(f"Failed: {url} - {e}")
