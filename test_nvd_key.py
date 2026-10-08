"""Quick test: verify NVD API key works and CVSS 4.0 data is returned."""
import asyncio
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def test():
    api_key = os.getenv("NVD_API_KEY")
    print(f"NVD API Key present: {bool(api_key)}")
    if api_key:
        print(f"Key (first 8 chars): {api_key[:8]}...")
    
    headers = {"apiKey": api_key} if api_key else {}
    
    test_cves = ["CVE-2024-26153", "CVE-2024-26155", "CVE-2024-1486", "CVE-2024-45493"]
    
    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        for cve_id in test_cves:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})
                    
                    v4 = metrics.get("cvssMetricV40", [])
                    v31 = metrics.get("cvssMetricV31", [])
                    
                    v4_score = v4[0]["cvssData"]["baseScore"] if v4 else "N/A"
                    v4_sev = v4[0]["cvssData"]["baseSeverity"] if v4 else "N/A"
                    v31_score = v31[0]["cvssData"]["baseScore"] if v31 else "N/A"
                    v31_sev = v31[0]["cvssData"]["baseSeverity"] if v31 else "N/A"
                    
                    print(f"\n{cve_id}:")
                    print(f"  CVSS 3.1: {v31_score} ({v31_sev})")
                    print(f"  CVSS 4.0: {v4_score} ({v4_sev})")
                else:
                    print(f"\n{cve_id}: Not found in NVD")
            else:
                print(f"\n{cve_id}: HTTP {resp.status_code}")
            await asyncio.sleep(0.8)  # With API key we can go faster

asyncio.run(test())
