import asyncio
import httpx

async def test_login():
    url = "http://127.0.0.1:8003/api/auth/login"
    payload = {
        "email": "nowfal@gmail.com",
        "password": "WrongPassword123!"
    }
    print(f"Sending POST to {url}...")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            print(f"Status Code: {resp.status_code}")
            print(f"Response: {resp.text}")
    except Exception as e:
        print(f"Request failed: {type(e).__name__}: {e}")

asyncio.run(test_login())
