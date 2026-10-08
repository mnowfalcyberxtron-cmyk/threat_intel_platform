import requests
import json

headers = {
    "x-rapidapi-host": "ics-ap-apis.p.rapidapi.com",
    "x-rapidapi-key": "a8806dc109mshcfc303b56af6919p1f219ejsn8fb9ad49250c"
}

endpoints = [
    "https://ics-ap-apis.p.rapidapi.com/vendors",
    "https://ics-ap-apis.p.rapidapi.com/advisories/latest",
    "https://ics-ap-apis.p.rapidapi.com/advisories",
    "https://ics-ap-apis.p.rapidapi.com/advisories/search"
]

print("Testing endpoints:")
for ep in endpoints:
    print(f"\n--- Calling {ep} ---")
    try:
        r = requests.get(ep, headers=headers, timeout=10)
        print(f"Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                print(f"Returned list of {len(data)} items.")
                if len(data) > 0:
                    print("Sample item structure:")
                    print(json.dumps(data[0], indent=2)[:1000])
            elif isinstance(data, dict):
                print(f"Returned dict with keys: {list(data.keys())}")
                # Print a bit of the dict
                print(json.dumps(data, indent=2)[:1000])
        else:
            print(f"Response: {r.text[:500]}")
    except Exception as e:
        print(f"Error calling {ep}: {e}")
