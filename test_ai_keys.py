import asyncio
import httpx
from config import settings

async def test_groq():
    print("Testing Groq...")
    if not settings.GROQ_API_KEY:
        print("[-] Groq: No key configured.")
        return
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 5
                },
                timeout=10.0
            )
            if resp.status_code == 200:
                print("[+] Groq: Key is WORKING.")
            else:
                print(f"[-] Groq: Failed with status {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[-] Groq: Error - {e}")

async def test_openrouter():
    print("\nTesting OpenRouter...")
    if not settings.OPENROUTER_API_KEY:
        print("[-] OpenRouter: No key configured.")
        return
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}"},
                json={
                    "model": "meta-llama/llama-3.1-8b-instruct:free",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 5
                },
                timeout=10.0
            )
            if resp.status_code == 200:
                print("[+] OpenRouter: Key is WORKING.")
            else:
                print(f"[-] OpenRouter: Failed with status {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[-] OpenRouter: Error - {e}")

async def main():
    await test_groq()
    await test_openrouter()

if __name__ == "__main__":
    asyncio.run(main())
