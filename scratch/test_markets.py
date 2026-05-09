import requests
r = requests.get('https://api.ransomware.live/v2/markets')
data = r.json()
print("Total Markets:", len(data))
print("First market:", data[0].get('name'))
