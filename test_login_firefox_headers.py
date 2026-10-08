import asyncio
import httpx

async def test():
    url = "http://127.0.0.1:8003/api/auth/login"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "http://127.0.0.1:8003/",
        "Content-Type": "application/json",
        "Origin": "http://127.0.0.1:8003",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin"
    }
    payload = {
        "email": "feedsautomate@gmail.com",
        "password": "Nowfal@20092003"
    }
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(url, json=payload, headers=headers)
            print("Status:", r.status_code)
            print("Response:", r.text)
        except Exception as e:
            print("Failed:", type(e).__name__, e)

asyncio.run(test())
