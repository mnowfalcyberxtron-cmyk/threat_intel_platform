import os
from dotenv import load_dotenv

def main():
    load_dotenv()
    rapidapi_key = os.getenv("RAPIDAPI_KEY")
    groq_key = os.getenv("GROQ_API_KEY")
    
    print("--- Checking configured API Keys ---")
    if rapidapi_key:
        print(f"RAPIDAPI_KEY: Present (Length: {len(rapidapi_key)})")
        print(f"  Prefix: {rapidapi_key[:4]}...{rapidapi_key[-4:] if len(rapidapi_key) > 8 else ''}")
    else:
        print("RAPIDAPI_KEY: Missing")
        
    if groq_key:
        print(f"GROQ_API_KEY: Present (Length: {len(groq_key)})")
        print(f"  Prefix: {groq_key[:4]}...{groq_key[-4:] if len(groq_key) > 8 else ''}")
    else:
        print("GROQ_API_KEY: Missing")

if __name__ == "__main__":
    main()
