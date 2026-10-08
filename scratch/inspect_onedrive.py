import requests

def main():
    url = "https://1drv.ms/x/c/58897f49075b1bc5/IQCbQQAZ3G0DQ7m06TMh0ECXAeugC9AdA_q_3AWMmc2gyVc?e=oyhDHZ"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    print("Sending GET to original URL...")
    r = requests.get(url, headers=headers, allow_redirects=True)
    print(f"Status: {r.status_code}")
    print(f"History: {r.history}")
    print(f"Final URL: {r.url}")
    
    # Save the HTML to inspect
    with open("scratch/onedrive_page.html", "w", encoding="utf-8") as f:
        f.write(r.text)
    print("Saved page to scratch/onedrive_page.html")

if __name__ == "__main__":
    main()
