import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('frontend/index.html', encoding='utf-8') as f:
    lines = f.readlines()

total = len(lines)
print(f"Total lines: {total}")

# Find nav-item for advisories
for i, line in enumerate(lines, 1):
    if 'data-view="advisories"' in line or 'data-view="advisory"' in line or 'ICS' in line:
        print(f"Line {i}: {line.rstrip()}")

print("\n--- Looking for view-advisories end ---")
for i, line in enumerate(lines, 1):
    if 'view-livefeed' in line or ('<!-- LIVE' in line):
        print(f"Line {i}: {line.rstrip()}")
        break

print("\n--- Looking for last JS function area ---")
for i, line in enumerate(lines, 1):
    if 'async function loadAdvisories' in line or 'function renderAdvCard' in line:
        print(f"Line {i}: {line.rstrip()}")
