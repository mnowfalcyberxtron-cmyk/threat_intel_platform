import re
from bs4 import BeautifulSoup

def main():
    with open("scratch/onedrive_page.html", "r", encoding="utf-8") as f:
        html = f.read()
        
    soup = BeautifulSoup(html, "html.parser")
    
    # 1. Search for download links
    download_links = []
    for a in soup.find_all("a", href=True):
        if "download" in a["href"].lower() or "download" in a.get_text().lower():
            download_links.append((a.get_text(), a["href"]))
            
    print(f"Found {len(download_links)} links matching 'download':")
    for txt, href in download_links:
        print(f"Text: {txt} | Link: {href}")
        
    # 2. Search for inline scripts with onedrive config or links
    scripts = soup.find_all("script")
    print(f"\nTotal scripts found: {len(scripts)}")
    
    # Look for patterns like downloadURL or personal url
    patterns = [
        r'https?://[a-zA-Z0-9.-]+\.live\.com/[a-zA-Z0-9/?=&_.-]+',
        r'downloadUrl',
        r'resid',
        r'sourcedoc'
    ]
    
    for i, s in enumerate(scripts):
        text = s.string or ""
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                # print a snippet of matching scripts
                print(f"Script {i} matches '{pat}':")
                # Print lines containing the match
                lines = text.split("\n")
                for line in lines:
                    if re.search(pat, line, re.IGNORECASE):
                        print(f"  {line[:200]}")
                        
if __name__ == "__main__":
    main()
