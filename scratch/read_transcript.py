import sys
import os
import json

try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    pass

log_path = r"C:\Users\xtronuser\.gemini\antigravity\brain\a03b205c-89fa-4896-bbc9-1eb52e2c41f5\.system_generated\logs\transcript.jsonl"

if not os.path.exists(log_path):
    print("Transcript log path does not exist!")
    sys.exit(0)

print("Searching transcript for telegram/channel references...")
with open(log_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            obj = json.loads(line)
            content = obj.get("content", "")
            if not content:
                continue
            if "telegram" in content.lower() or "channel" in content.lower() or "tg" in content.lower():
                print(f"[{obj.get('source')}] {content[:200]}...")
                print("-" * 50)
        except Exception as e:
            pass
