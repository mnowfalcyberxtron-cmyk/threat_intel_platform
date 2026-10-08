import sqlite3
import httpx
import asyncio

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def check_nvd_cvss(cve_id: str):
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
        if resp.status_code != 200:
            print(f"{cve_id}: HTTP {resp.status_code}")
            return
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"{cve_id}: Not found in NVD")
            return
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        v40 = metrics.get("cvssMetricV40", [])
        if v40:
            score = v40[0].get("cvssData", {}).get("baseScore")
            sev = v40[0].get("cvssData", {}).get("baseSeverity")
            print(f"{cve_id}: CVSS 4.0: {score} ({sev})")
        else:
            print(f"{cve_id}: No CVSS 4.0")

async def main():
    conn = sqlite3.connect('data/threat_intel.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Get recent CVEs (2024 or 2025)
    cursor.execute("SELECT DISTINCT cve_id FROM ics_advisories WHERE cve_id LIKE 'CVE-2024-%' OR cve_id LIKE 'CVE-2025-%' ORDER BY id DESC LIMIT 5")
    rows = cursor.fetchall()
    
    for row in rows:
        await check_nvd_cvss(row["cve_id"])
        await asyncio.sleep(6)  # NVD rate limit: ~5 req/30s without API key

asyncio.run(main())
