import urllib.request, json
import sqlite3

try:
    req = urllib.request.Request('http://localhost:8002/api/advisory/')
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode())
    print("API Advisories Count:", len(data.get("items", [])))
except Exception as e:
    print("API Advisories Error:", e)

try:
    conn = sqlite3.connect('data/threat_intel.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM advisories WHERE fetched_at>=datetime('now','-168 hours')")
    print("DB DB Count:", c.fetchone()[0])
except Exception as e:
    print("DB Error:", e)
