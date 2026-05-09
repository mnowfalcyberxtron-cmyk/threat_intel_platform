import urllib.request, json
try:
    req = urllib.request.Request('http://localhost:8002/api/advisory/?search=microsoft')
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode())
    print("API Advisories Microsoft Search Count:", len(data.get("items", [])))
except Exception as e:
    print("API Error:", e)

try:
    req = urllib.request.Request('http://localhost:8002/api/advisory/?company=microsoft')
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode())
    print("API Advisories Microsoft Company Count:", len(data.get("items", [])))
except Exception as e:
    print("API Error:", e)

try:
    req = urllib.request.Request('http://localhost:8002/api/advisory/?hours=168')
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode())
    print("API Advisories Hours 168 Count:", len(data.get("items", [])))
except Exception as e:
    print("API Error:", e)
