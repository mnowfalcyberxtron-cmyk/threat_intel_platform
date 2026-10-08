import urllib.request
import urllib.parse
import json

# 1. Login to get token
url_login = "http://localhost:8006/api/auth/token"
data = urllib.parse.urlencode({"username": "admin", "password": "ThreatIntel_Secret_2026!"}).encode()
req = urllib.request.Request(url_login, data=data)
try:
    with urllib.request.urlopen(req) as response:
        token = json.loads(response.read())['access_token']

    # 2. Fetch /meta
    req_meta = urllib.request.Request("http://localhost:8006/api/advisory/ics/meta")
    req_meta.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req_meta) as response:
        meta = json.loads(response.read())
        print("META KEYS:", list(meta.keys()))
        if 'cve_pub_years' in meta:
            print("cve_pub_years:", meta['cve_pub_years'])
        else:
            print("cve_pub_years IS MISSING!")
except Exception as e:
    print("Error:", e)
