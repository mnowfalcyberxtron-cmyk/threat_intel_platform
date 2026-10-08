import requests
import json

url = "https://api.github.com/repos/icsadvprj/ICS-Advisory-Project/contents/ICS-CERT_ADV"
headers = {"User-Agent": "Mozilla/5.0"}
try:
    r = requests.get(url, headers=headers, timeout=10)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        items = r.json()
        print(f"Total items in ICS-CERT_ADV: {len(items)}")
        for item in items[:30]:
            print(f"- {item['name']} ({item['type']})")
    else:
        print(r.text)
except Exception as e:
    print(f"Error: {e}")
