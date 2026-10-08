from bs4 import BeautifulSoup
import json
import re

def main():
    with open("scratch/onedrive_page.html", "r", encoding="utf-8") as f:
        html = f.read()
        
    soup = BeautifulSoup(html, "html.parser")
    print("Page title:", soup.title.string if soup.title else "No title")
    
    # Let's see if we can find document title in scripts or body
    m = re.search(r'"FileName"\s*:\s*("[^"]*")', html)
    if m:
        print("Filename found:", m.group(1))
    else:
        print("Filename not found by regex")
        
    # Search for all occurences of "FileName" or similar variables
    for line in html.split("\n"):
        if "FileName" in line or "Title" in line:
            if len(line) < 200:
                print("Line:", line.strip())

if __name__ == "__main__":
    main()
