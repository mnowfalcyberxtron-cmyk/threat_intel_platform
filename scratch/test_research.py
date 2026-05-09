import requests
from duckduckgo_search import DDGS

print("DuckDuckGo Test:")
try:
    results = DDGS().text("qilin ransomware", max_results=2)
    print("DDG Results:", list(results))
except Exception as e:
    print("DDG Error:", e)

print("\nRansomlook Market API Test:")
try:
    # They have /api/markets maybe? Or /api/groups?
    r = requests.get('https://api.ransomlook.io/api/markets', timeout=10)
    print("Markets:", r.status_code, r.text[:200])
except Exception as e:
    print("Market Error:", e)

try:
    r = requests.get('https://api.ransomlook.io/api/groups', timeout=10)
    print("Groups:", r.status_code, r.text[:200])
except Exception as e:
    print("Groups Error:", e)
