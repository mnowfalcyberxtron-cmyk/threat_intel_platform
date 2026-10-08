with open("frontend/index.html", "r", encoding="utf-8") as f:
    html = f.read()

import re

items = re.findall(r'<[^>]*class="[^"]*nav-item[^"]*"[^>]*>.*?</[^>]+>', html, re.DOTALL | re.IGNORECASE)
output = []
output.append(f"Found {len(items)} nav items:")
for item in items:
    clean_text = re.sub(r'<[^>]+>', ' ', item).strip()
    output.append(f"- {clean_text} (HTML: {item.strip()})")

with open("scratch/nav_items_output.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(output))
