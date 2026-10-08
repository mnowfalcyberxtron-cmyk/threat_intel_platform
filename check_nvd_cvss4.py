"""Test NVD API v2 for CVSS 4.0 scores on recent CVEs."""
import httpx
import asyncio
import json

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def check_nvd_cvss(cve_id: str):
    """Fetch a CVE from NVD and check for CVSS 4.0 vs 3.1."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
        if resp.status_code != 200:
            print(f"  {cve_id}: HTTP {resp.status_code}")
            return
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"  {cve_id}: Not found in NVD")
            return
        
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        
        # Check CVSS 4.0
        v40 = metrics.get("cvssMetricV40", [])
        v31 = metrics.get("cvssMetricV31", [])
        v30 = metrics.get("cvssMetricV30", [])
        v2  = metrics.get("cvssMetricV2", [])
        
        print(f"  {cve_id}:")
        if v40:
            score = v40[0].get("cvssData", {}).get("baseScore")
            sev = v40[0].get("cvssData", {}).get("baseSeverity")
            vec = v40[0].get("cvssData", {}).get("vectorString", "")
            print(f"    CVSS 4.0: {score} ({sev}) — {vec}")
        if v31:
            score = v31[0].get("cvssData", {}).get("baseScore")
            sev = v31[0].get("cvssData", {}).get("baseSeverity")
            print(f"    CVSS 3.1: {score} ({sev})")
        if v30:
            score = v30[0].get("cvssData", {}).get("baseScore")
            sev = v30[0].get("cvssData", {}).get("baseSeverity")
            print(f"    CVSS 3.0: {score} ({sev})")
        if v2:
            score = v2[0].get("cvssData", {}).get("baseScore")
            print(f"    CVSS 2.0: {score}")
        if not (v40 or v31 or v30 or v2):
            print(f"    No CVSS data available")

async def main():
    # Test with recent CVEs from the DB
    import sqlite3
    conn = sqlite3.connect('data/threat_intel.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT cve_id, cvss_score FROM ics_advisories WHERE cve_id != 'N/A' ORDER BY updated_at DESC LIMIT 10")
    rows = cursor.fetchall()
    
    print("=== NVD CVSS 4.0 vs 3.1 comparison ===\n")
    for row in rows:
        cve_id = row["cve_id"]
        db_score = row["cvss_score"]
        print(f"DB Score: {db_score}")
        await check_nvd_cvss(cve_id)
        await asyncio.sleep(0.7)  # NVD rate limit: ~5 req/30s without API key
        print()

asyncio.run(main())
