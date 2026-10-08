import requests
import json

def get_contents(path=""):
    url = f"https://api.github.com/repos/icsadvprj/ICS-Advisory-Project/contents/{path}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            items = r.json()
            for item in items:
                if item['type'] == 'dir':
                    # Skip archive to avoid hitting rate limits
                    if item['name'] != 'ICS-CERT_ADV_Archive':
                        get_contents(item['path'])
                else:
                    print(f"- {item['path']} ({item['size']} bytes)")
        else:
            print(f"Error {path}: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"Error {path}: {e}")

print("Listing all files in repository:")
get_contents()
