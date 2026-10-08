"""
Probe the ICS RapidAPI to discover the actual field names returned
by the /products and /advisories endpoints.
"""
import asyncio
import httpx
import json
import os
from dotenv import load_dotenv

load_dotenv()
KEY = os.getenv("RAPIDAPI_KEY")
HOST = "ics-ap-apis.p.rapidapi.com"
BASE = f"https://{HOST}"
HEADERS = {
    "x-rapidapi-host": HOST,
    "x-rapidapi-key": KEY,
    "Accept": "application/json",
}

async def probe():
    async with httpx.AsyncClient(timeout=30) as client:

        # 1. products endpoint
        print("=== GET /products ===")
        r = await client.get(f"{BASE}/products", headers=HEADERS)
        payload = r.json()
        result = payload.get("result", payload) if isinstance(payload, dict) else payload
        items = result if isinstance(result, list) else [result]
        if items:
            print("Keys:", list(items[0].keys()))
            print(json.dumps(items[0], indent=2)[:1500])

        print()
        print("=== GET /advisories/latest/1 ===")
        r = await client.get(f"{BASE}/advisories/latest/1", headers=HEADERS)
        payload = r.json()
        result = payload.get("result", payload) if isinstance(payload, dict) else payload
        items = result if isinstance(result, list) else [result]
        if items:
            print("Latest summary keys:", list(items[0].keys()))
            ics_id = items[0].get("ICS-CERT_Number") or items[0].get("ics_number")
            print("Sample ICS ID:", ics_id)

            if ics_id:
                print()
                print(f"=== GET /advisories/{ics_id} ===")
                r2 = await client.get(f"{BASE}/advisories/{ics_id}", headers=HEADERS)
                detail = r2.json()
                dr = detail.get("result", detail) if isinstance(detail, dict) else detail
                ditems = dr if isinstance(dr, list) else [dr]
                if ditems:
                    print("Detail keys:", list(ditems[0].keys()))
                    print(json.dumps(ditems[0], indent=2)[:3000])

asyncio.run(probe())
