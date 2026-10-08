import json
import re

def main():
    with open("scratch/onedrive_page.html", "r", encoding="utf-8") as f:
        html = f.read()
        
    # Search for _wopiContextJson definition
    m = re.search(r'var _wopiContextJson\s*=\s*(\{.*?\});', html)
    if m:
        wopi_str = m.group(1)
        print("Found _wopiContextJson!")
        try:
            wopi = json.loads(wopi_str)
            for k, v in wopi.items():
                if "url" in k.lower() or "get" in k.lower() or "download" in k.lower():
                    print(f"Key: {k} -> {v}")
        except Exception as e:
            print("Failed to parse JSON:", e)
            print(wopi_str[:500])
    else:
        print("_wopiContextJson not found by regex")
        # Try direct search for FileGetUrl
        m2 = re.search(r'"FileGetUrl"\s*:\s*("[^"]*")', html)
        if m2:
            print(f"Direct match for FileGetUrl: {m2.group(1)}")
            
if __name__ == "__main__":
    main()
