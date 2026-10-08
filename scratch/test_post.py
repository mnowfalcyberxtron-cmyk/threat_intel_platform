import requests
import os
import sys
from dotenv import load_dotenv

load_dotenv()

def test_mb():
    url = "https://mb-api.abuse.ch/api/v1/"
    # The Auth-Key is unified for all abuse.ch projects
    api_key = os.getenv("THREATFOX_API_KEY")
    print(f"Loaded unified Auth-Key: {api_key}")
    
    headers = {
        "Content-Type": "application/json", 
        "User-Agent": "ThreatIntel-TIP/2.2",
        "Auth-Key": api_key
    }
    json_data = {"query": "get_recent", "selector": "time"}
    print(f"Testing MalwareBazaar via POST {url} using Auth-Key...")
    try:
        resp = requests.post(url, json=json_data, headers=headers, verify=False, timeout=15)
        print(f"Status: {resp.status_code}")
        print(f"Headers: {resp.headers}")
        print(f"Content (first 500 chars): {resp.text[:500]}")
    except Exception as e:
        print(f"Error testing MalwareBazaar: {type(e).__name__}: {e}")

def test_tf():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    api_key = os.getenv("THREATFOX_API_KEY")
    
    headers = {
        "Content-Type": "application/json", 
        "User-Agent": "ThreatIntel-TIP/2.2",
        "Auth-Key": api_key
    }
    json_data = {"query": "get_iocs", "days": 1}
    print(f"Testing ThreatFox via POST {url} using Auth-Key...")
    try:
        resp = requests.post(url, json=json_data, headers=headers, verify=False, timeout=15)
        print(f"Status: {resp.status_code}")
        print(f"Headers: {resp.headers}")
        print(f"Content (first 500 chars): {resp.text[:500]}")
    except Exception as e:
        print(f"Error testing ThreatFox: {type(e).__name__}: {e}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    test_mb()
    print("-" * 50)
    test_tf()
