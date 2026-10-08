import asyncio
import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, ".")
load_dotenv()

from engine.ai_engine import AIEngine
from config import settings
from database.db import Database

async def test_providers():
    db = Database()
    await db.initialize()
    engine = AIEngine(db)
    
    messages = [{"role": "user", "content": "Hello, simply reply with the word 'SUCCESS' and your model name."}]
    tools = [] # Empty tools list for a basic chat completion test via the tool pipeline
    
    print("--- Testing Groq ---")
    try:
        resp = await engine._groq_tools(messages, tools)
        print("Groq Response:", repr(resp))
    except Exception as e:
        print("Groq Failed:", e)
        
    print("\n--- Testing OpenRouter ---")
    try:
        resp = await engine._openrouter_tools(messages, tools)
        print("OpenRouter Response:", repr(resp))
    except Exception as e:
        print("OpenRouter Failed:", e)
        
    print("\n--- Testing Fallback Logic (AI_PROVIDER=groq) ---")
    try:
        settings.AI_PROVIDER = "groq"
        # Test normally, should use Groq
        resp = await engine._complete_with_tools(messages, tools)
        print("Cascade (Groq Primary) Response:", repr(resp))
        
        # Now artificially break Groq to test fallback
        old_key = settings.GROQ_API_KEY
        settings.GROQ_API_KEY = "invalid_key_to_force_fallback"
        print("\nBreaking Groq key to force fallback...")
        resp2 = await engine._complete_with_tools(messages, tools)
        print("Cascade (Fallen back to OpenRouter) Response:", repr(resp2))
        
        # Restore
        settings.GROQ_API_KEY = old_key
        
    except Exception as e:
        print("Cascade Failed:", e)

    await db.close()

asyncio.run(test_providers())
