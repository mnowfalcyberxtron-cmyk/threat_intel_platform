import base64
import requests
import os

def get_onedrive_direct_link(sharing_url):
    base64_bytes = base64.b64encode(sharing_url.encode('utf-8'))
    base64_string = base64_bytes.decode('utf-8')
    clean_base64 = base64_string.replace('+', '-').replace('/', '_').rstrip('=')
    return f"https://api.onedrive.com/v1.0/shares/u!{clean_base64}/root/content"

def main():
    url = "https://1drv.ms/x/c/58897f49075b1bc5/IQCbQQAZ3G0DQ7m06TMh0ECXAeugC9AdA_q_3AWMmc2gyVc?e=oyhDHZ"
    direct_url = get_onedrive_direct_link(url)
    print(f"Direct download URL: {direct_url}")
    
    output_path = "scratch/threat_intel_input.xlsx"
    print("Downloading Excel...")
    response = requests.get(direct_url, allow_redirects=True)
    if response.status_code == 200:
        with open(output_path, "wb") as f:
            f.write(response.content)
        print(f"Downloaded successfully to {output_path} (Size: {len(response.content)} bytes)")
    else:
        print(f"Failed to download. Status code: {response.status_code}")
        print(response.text[:200])

if __name__ == "__main__":
    main()
