import requests
import json
import os

headers = {
    "x-rapidapi-host": "ics-ap-apis.p.rapidapi.com",
    "x-rapidapi-key": os.getenv("RAPIDAPI_KEY", os.getenv("ICS_RAPIDAPI_KEY", ""))
}

endpoints = [
    "https://ics-ap-apis.p.rapidapi.com/advisories/ICSA-26-111-03",
    "https://ics-ap-apis.p.rapidapi.com/advisories/search?vendor=Siemens",
    "https://ics-ap-apis.p.rapidapi.com/advisories/search?q=Siemens",
    "https://ics-ap-apis.p.rapidapi.com/products/search?vendor=Siemens"
]

print("Testing endpoints:")
for ep in endpoints:
    print(f"\n--- Calling {ep} ---")
    try:
        r = requests.get(ep, headers=headers, timeout=10)
        print(f"Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print("Response preview:")
            print(json.dumps(data, indent=2)[:2000])
        else:
            print(f"Response: {r.text[:1000]}")
    except Exception as e:
        print(f"Error calling {ep}: {e}")
