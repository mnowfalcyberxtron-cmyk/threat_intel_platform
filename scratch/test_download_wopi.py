import json
import re
import requests

def main():
    with open("scratch/onedrive_page.html", "r", encoding="utf-8") as f:
        html = f.read()
        
    m = re.search(r'var _wopiContextJson\s*=\s*(\{.*?\});', html)
    if not m:
        print("Failed to find _wopiContextJson")
        return
        
    try:
        wopi = json.loads(m.group(1))
        file_get_url = wopi.get("FileGetUrl")
        if not file_get_url:
            print("FileGetUrl key not found in _wopiContextJson")
            return
            
        print(f"Extracted FileGetUrl: {file_get_url[:100]}...")
        
        output_path = "scratch/threat_intel_input.xlsx"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        print("Downloading file via FileGetUrl...")
        r = requests.get(file_get_url, headers=headers, allow_redirects=True)
        print(f"Status: {r.status_code}")
        print(f"Content-type: {r.headers.get('Content-Type')}")
        print(f"Content-length: {len(r.content)} bytes")
        
        if r.status_code == 200:
            with open(output_path, "wb") as f_out:
                f_out.write(r.content)
            print(f"Successfully downloaded to {output_path}!")
        else:
            print("Failed to download. Content snippet:")
            print(r.text[:300])
            
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
