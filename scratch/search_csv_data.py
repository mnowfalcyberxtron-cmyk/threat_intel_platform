import requests
import csv
import io

url = "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"
headers = {"User-Agent": "Mozilla/5.0"}

try:
    r = requests.get(url, headers=headers, stream=True, timeout=15)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        csv_text = r.text
        reader = csv.DictReader(io.StringIO(csv_text))
        
        matches = []
        for row in reader:
            # Search for PCM600 or the CVE
            cves = row.get("CVE_Number", "")
            title = row.get("ICS-CERT_Advisory_Title", "")
            vendor = row.get("Vendor", "")
            if "PCM600" in title or "PCM600" in row.get("Product", "") or "CVE-2019-1002309" in cves:
                matches.append(row)
        
        print(f"Found {len(matches)} matching rows:")
        for idx, match in enumerate(matches):
            print(f"\nMatch {idx+1}:")
            for k, v in match.items():
                print(f"  {k}: {v}")
    else:
        print(r.text)
except Exception as e:
    print(f"Error: {e}")
