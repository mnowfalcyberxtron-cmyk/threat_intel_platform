import asyncio
import httpx
import os

# Manual load from .env
keys = {}
with open(".env", "r") as f:
    for line in f:
        if "=" in line:
            k, v = line.strip().split("=", 1)
            keys[k] = v

async def test_key(name, url, headers, payload):
    print(f"Testing {name}...")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, json=payload, timeout=10.0)
            if resp.status_code == 200:
                print(f"[+] {name}: WORKING.")
                return True
            else:
                print(f"[-] {name}: Failed ({resp.status_code}) - {resp.text}")
                return False
    except Exception as e:
        print(f"[-] {name}: Error - {e}")
        return False

async def main():
    # Test OpenRouter
    or_key = keys.get("OPENROUTER_API_KEY")
    if or_key:
        await test_key("OpenRouter", 
                       "https://openrouter.ai/api/v1/chat/completions",
                       {"Authorization": f"Bearer {or_key}"},
                       {"model": keys.get("OPENROUTER_MODEL", "openai/gpt-4o-mini"), 
                        "messages": [{"role": "user", "content": "hi"}]})
    
    # Test Groq
    groq_key = keys.get("GROQ_API_KEY")
    if groq_key:
        await test_key("Groq",
                       "https://api.groq.com/openai/v1/chat/completions",
                       {"Authorization": f"Bearer {groq_key}"},
                       {"model": keys.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
                        "messages": [{"role": "user", "content": "hi"}]})

if __name__ == "__main__":
    asyncio.run(main())
