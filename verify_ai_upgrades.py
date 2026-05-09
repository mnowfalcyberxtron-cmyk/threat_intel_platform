import asyncio
import httpx
import json
import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

from config import settings
from engine.ai_engine import AIEngine
from database.db import Database

async def test_health():
    print("Testing AI Health Check...")
    ai = AIEngine()
    health = await ai.get_ai_health()
    print(json.dumps(health, indent=2))
    await ai.close()

async def test_agent():
    print("\nTesting Modular Agent...")
    db = Database()
    await db.initialize()
    ai = AIEngine(db=db)
    
    # Use OpenRouter for the test if configured
    if settings.OPENROUTER_API_KEY:
        settings.AI_PROVIDER = "openrouter"
        ai.provider = "openrouter"
        print(f"Using OpenRouter model: {settings.OPENROUTER_MODEL}")
        
        try:
            # Ask a question that requires tool use
            # "Who are the top threat actors in the database?"
            response = await ai.chat_agent("What are the most recent ransomware victims reported in our database?")
            print("\nAgent Response:")
            print(response)
        except Exception as e:
            print(f"Agent Error: {e}")
    else:
        print("OpenRouter not configured, skipping agent test.")
    
    await ai.close()
    await db.close()

if __name__ == "__main__":
    asyncio.run(test_health())
    # asyncio.run(test_agent()) # Uncomment to test agent (requires valid API key)
