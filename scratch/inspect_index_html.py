with open("frontend/index.html", "r", encoding="utf-8") as f:
    html = f.read()

import re

# Find tab buttons or navigation links
print("Tabs/Nav Links found:")
navs = re.findall(r'<a\b[^>]*role="tab"[^>]*>.*?</a>|<button\b[^>]*role="tab"[^>]*>.*?</button>|<a\b[^>]*class="[^"]*nav[^"]*"[^>]*>.*?</a>', html, re.DOTALL | re.IGNORECASE)
for nav in navs[:20]:
    # clean tag to show text
    text = re.sub(r'<[^>]+>', '', nav).strip()
    print(f"- {text} (HTML: {nav.strip()})")

print("\nSections with ID:")
ids = re.findall(r'id="([^"]+)"', html)
for id_val in ids:
    if any(k in id_val.lower() for k in ["tab", "sec", "container", "panel", "advisory"]):
        print(f"- {id_val}")
