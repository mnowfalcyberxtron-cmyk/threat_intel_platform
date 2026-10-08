import sys
sys.stdout.reconfigure(encoding='utf-8')

with open("api/advisory_routes.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    # print the lines near 450 to 520
    if 450 <= i+1 <= 520:
        print(f"{i+1}: {line.rstrip()}")
