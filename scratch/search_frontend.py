import re

def main():
    with open("frontend/index.html", "r", encoding="utf-8") as f:
        html = f.read()
        
    print(f"index.html length: {len(html)}")
    
    # 1. Search for Month filter in dropdowns
    print("\n--- Searching for month filter dropdowns ---")
    matches = re.findall(r'<select[^>]*id="[^"]*month[^"]*"[^>]*>.*?</select>', html, re.DOTALL | re.IGNORECASE)
    for m in matches[:5]:
        print(m[:300])
        
    # 2. Search for /api/advisory/ics references
    print("\n--- Searching for /api/advisory/ics references ---")
    lines = html.split("\n")
    for i, line in enumerate(lines):
        if "/api/advisory/ics" in line or "ics-month" in line or "loadIcsCves" in line:
            print(f"Line {i+1}: {line.strip()[:200]}")
            
    # 3. Search for ics panels
    print("\n--- Searching for ics-cve-panel or similar ---")
    for i, line in enumerate(lines):
        if 'id="ics' in line or 'class="ics' in line or 'ics-cve' in line:
            print(f"Line {i+1}: {line.strip()[:200]}")

if __name__ == "__main__":
    main()
