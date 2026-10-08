with open("frontend/index.html", "r", encoding="utf-8") as f:
    html = f.read()

import re

# Find divs with id="advisory" or id="advisories" or data-view matching them
# Often they have class="panel" or are hidden/visible depending on nav
# Let's search for id="advisory" and id="advisories" containers
def print_container(container_id):
    # Find <div id="container_id" ... > ... </div>
    pattern = rf'<div\b[^>]*id="{container_id}"[^>]*>.*?</div>'
    match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
    if match:
        print(f"--- Container: {container_id} ---")
        print(match.group(0)[:1500])
        print("...")
    else:
        # Try finding section or other tags
        pattern = rf'<section\b[^>]*id="{container_id}"[^>]*>.*?</section>'
        match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
        if match:
            print(f"--- Container (section): {container_id} ---")
            print(match.group(0)[:1500])
            print("...")
        else:
            print(f"Container {container_id} not found by direct regex")

print_container("advisory")
print_container("advisories")
