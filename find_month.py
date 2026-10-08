content = open('frontend/index.html', 'r', encoding='utf-8').read()
import re

# Find ics-month references
matches = list(re.finditer(r'ics.month', content, re.IGNORECASE))
print(f"Total 'ics-month' occurrences: {len(matches)}")
for m in matches[:15]:
    print(f"\npos {m.start()}: {content[max(0,m.start()-20):m.start()+200]}")
    print("---")
