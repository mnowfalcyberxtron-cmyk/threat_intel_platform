with open("frontend/index.html", "r", encoding="utf-8") as f:
    html = f.read()

import re

# Let's search for buttons/list items inside a <nav> or sidebar container
sidebar_start = html.find("sidebar")
if sidebar_start != -1:
    print("Found sidebar in html! Extracting nearby content...")
    print(html[sidebar_start-500:sidebar_start+2000])
else:
    # Print lines that look like navigation links
    print("Sidebar not found by class. Let's find button or nav elements:")
    btns = re.findall(r'<button\b[^>]*>.*?</button>|<li\b[^>]*>.*?</li>|<div\b[^>]*class="[^"]*nav[^"]*"[^>]*>.*?</div>', html, re.DOTALL | re.IGNORECASE)
    for btn in btns[:30]:
        text = re.sub(r'<[^>]+>', '', btn).strip()
        if text and len(text) < 40:
            print(f"- {text} (HTML snippet: {btn[:150].strip()})")
