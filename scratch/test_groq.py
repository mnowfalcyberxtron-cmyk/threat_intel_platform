import os
import httpx
import asyncio
from dotenv import load_dotenv

load_dotenv()

async def test_groq():
    api_key = os.getenv("GROQ_API_KEY")
    models_to_test = [
        "llama-3.2-3b-preview", "llama-3.2-1b-preview", "llama-3.2-11b-vision-preview",
        "llama-3.2-90b-text-preview", "llama-3.3-70b-specdec"
    ]
    
    async with httpx.AsyncClient() as client:
        for model in models_to_test:
            print(f"\nTesting {model}...")
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "hi"}]
                }
            )
            print("STATUS:", resp.status_code)
            if resp.status_code != 200:
                print("ERROR:", resp.text)
            else:
                print("SUCCESS")
        resp = await client.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {api_key}"}
        )
        data = resp.json()
        for m in data.get("data", []):
            print(m["id"])

asyncio.run(test_groq())
