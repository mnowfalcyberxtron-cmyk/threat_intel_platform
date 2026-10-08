import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

print("Searching Python files for 'rapidapi' or 'ics-ap-apis'...")
found = False
for root, dirs, files in os.walk('.'):
    if 'venv' in root or '.git' in root or '__pycache__' in root:
        continue
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            try:
                with open(path, encoding='utf-8') as f:
                    content = f.read()
                if 'rapidapi' in content.lower() or 'ics-ap-apis' in content.lower():
                    print(f"Found match in: {path}")
                    found = True
            except Exception as e:
                pass
if not found:
    print("No matches found in Python files.")
