import httpx
import asyncio

async def main():
    print("Sending request to local HIBR investigation route...")
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            client.cookies.set("session_token", "0:feedsautomate@gmail.com")
            # First try without refresh to see if it's cached or returns 500
            response = await client.get("http://127.0.0.1:8006/api/hibr/investigate/domain/basilicfly.com")
            print("Status Code:", response.status_code)
            if response.status_code == 500:
                print("500 Response Body:")
                print(response.text)
            else:
                print("Response starts with:")
                print(response.text[:200])
    except Exception as e:
        print("Error connecting:", e)

if __name__ == '__main__':
    asyncio.run(main())
