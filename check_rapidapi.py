import httpx
import asyncio
import json
import os

RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY", os.getenv("ICS_RAPIDAPI_KEY", ""))
RAPIDAPI_HOST = "ics-ap-apis.p.rapidapi.com"
RAPIDAPI_BASE_URL = f"https://{RAPIDAPI_HOST}"

async def main():
    headers = {
        "x-rapidapi-host": RAPIDAPI_HOST,
        "x-rapidapi-key": RAPIDAPI_KEY,
        "Accept": "application/json",
    }
    
    async with httpx.AsyncClient(timeout=30) as client:
        # Get latest advisories
        print("Fetching latest 3 advisories...")
        res = await client.get(f"{RAPIDAPI_BASE_URL}/advisories/latest/3", headers=headers)
        if res.status_code != 200:
            print(f"Failed to get latest: {res.status_code} {res.text}")
            return
            
        data = res.json()
        print(f"Got {len(data)} summary items\n")
        
        for item in data[:1]:
            print("=== SUMMARY ITEM KEYS ===")
            for k, v in item.items():
                print(f"  {k}: {v}")
            
            advisory_id = item.get("ICS-CERT_Number") or item.get("ics_number")
            if advisory_id:
                print(f"\n=== DETAIL for {advisory_id} ===")
                detail_res = await client.get(f"{RAPIDAPI_BASE_URL}/advisories/{advisory_id}", headers=headers)
                if detail_res.status_code == 200:
                    detail_data = detail_res.json()
                    # Print ALL keys at every level
                    if isinstance(detail_data, list):
                        for i, entry in enumerate(detail_data[:2]):
                            print(f"\n--- Detail entry {i} ---")
                            for k, v in entry.items():
                                val_str = str(v)[:200]
                                print(f"  {k}: {val_str}")
                    elif isinstance(detail_data, dict):
                        for k, v in detail_data.items():
                            val_str = str(v)[:200]
                            print(f"  {k}: {val_str}")
                    
                    # Specifically look for CVSS-related keys
                    print("\n=== CVSS-RELATED KEYS ===")
                    def find_cvss_keys(obj, prefix=""):
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if 'cvss' in k.lower() or 'score' in k.lower() or 'severity' in k.lower():
                                    print(f"  {prefix}{k}: {v}")
                                find_cvss_keys(v, prefix + k + ".")
                        elif isinstance(obj, list):
                            for i, item in enumerate(obj[:3]):
                                find_cvss_keys(item, prefix + f"[{i}].")
                    
                    find_cvss_keys(detail_data)
                else:
                    print(f"  Detail fetch failed: {detail_res.status_code}")

asyncio.run(main())
