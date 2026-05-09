import requests
try:
    r = requests.get('https://api.ransomware.live/v2/groups')
    print("api/v2/groups:", len(r.json()))
except Exception as e:
    print("v2:", e)
try:
    r = requests.get('https://data.ransomware.live/groups')
    print("data/groups:", len(r.json()))
except Exception as e:
    print("data:", e)
