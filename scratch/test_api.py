import requests
r = requests.get('http://127.0.0.1:8002/api/rl/groups/detailed')
if r.status_code == 200:
    data = r.json()
    print("Success! Groups returned:", len(data.get("groups", [])))
else:
    print(r.status_code, r.text)
