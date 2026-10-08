import asyncio
import httpx

async def main():
    headers = {
        "X-User-ID": "0",
    }
    cookies = {
        "session_token": "0:feedsautomate@gmail.com"
    }
    async with httpx.AsyncClient(timeout=30) as client:
        # Check meta
        resp = await client.get("http://localhost:8003/api/advisory/ics/meta", headers=headers, cookies=cookies)
        print("Meta Status:", resp.status_code)
        if resp.status_code == 200:
            meta = resp.json()
            print("Meta Months (first 10):", meta.get("months")[:10])
            print("Meta Years (first 10):", meta.get("years")[:10])
            
            # Check filtering by first year and month
            if meta.get("years") and meta.get("months"):
                y = meta["years"][0]
                m = meta["months"][0][0]
                print(f"Testing filter: year={y}, month={m}")
                resp_filtered = await client.get(
                    f"http://localhost:8003/api/advisory/ics?year={y}&month={m}&page_size=5",
                    headers=headers,
                    cookies=cookies
                )
                print("Filtered Status:", resp_filtered.status_code)
                if resp_filtered.status_code == 200:
                    data = resp_filtered.json()
                    print(f"Total found for year={y}, month={m}: {data.get('total')}")
                    print("Sample items:")
                    for item in data.get("items", []):
                        print(f"CVE: {item.get('cve_id')}, Month: {item.get('month') or item.get('published_month')}, Date: {item.get('published_date')}")

asyncio.run(main())
