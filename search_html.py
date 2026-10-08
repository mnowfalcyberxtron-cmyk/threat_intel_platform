import sys
sys.stdout.reconfigure(encoding='utf-8')

with open("frontend/index.html", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "ics" in line.lower() and i+1 > 2000:
        print(f"{i+1}: {line.strip()[:120]}")
