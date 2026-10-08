import re

def main():
    with open("scratch/onedrive_page.html", "r", encoding="utf-8") as f:
        html = f.read()
        
    print(f"HTML size: {len(html)} characters")
    
    # Search for onion or market keywords
    keywords = [
        r'\.onion\b',
        r'onion',
        r'market',
        r'breach',
        r'ransomware',
        r'http'
    ]
    
    for kw in keywords:
        matches = list(re.finditer(kw, html, re.IGNORECASE))
        print(f"Keyword '{kw}': {len(matches)} matches")
        # Print a few samples if found
        if matches:
            for m in matches[:5]:
                start = max(0, m.start() - 50)
                end = min(len(html), m.end() + 50)
                snippet = html[start:end].replace('\n', ' ')
                print(f"  Snippet: ... {snippet} ...")

if __name__ == "__main__":
    main()
