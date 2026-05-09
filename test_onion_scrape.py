"""
test_onion_scrape.py — Tests if .onion scraping is possible via Tor.
Checks Tor connectivity, then tries a live scrape of a well-known .onion address.
"""
import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from config import settings

TOR_CHECK_URL = "https://check.torproject.org/api/ip"
# DuckDuckGo's official .onion — the most reliable test target
TEST_ONION_URL = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"

async def test_tor_and_scrape():
    print("=" * 60)
    print("  CyberXTron — .onion Scraping Capability Test")
    print(f"  Tor Proxy: {settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}")
    print("=" * 60)

    # Step 1: Test Tor connectivity
    print("\n[1] Testing Tor proxy connectivity...")
    tor_proxy = f"socks5://{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}"
    try:
        connector = ProxyConnector.from_url(tor_proxy)
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(TOR_CHECK_URL) as resp:
                data = await resp.json()
                is_tor = data.get("IsTor", False)
                exit_ip = data.get("IP", "unknown")
                if is_tor:
                    print(f"    [OK] Tor is ACTIVE. Exit IP: {exit_ip}")
                else:
                    print(f"    [WARN] Connected but not through Tor. IP: {exit_ip}")
    except Exception as e:
        print(f"    [FAIL] Tor proxy NOT reachable: {e}")
        print("\n  RESULT: .onion scraping is NOT possible right now.")
        print("  FIX: Start Tor Browser or run: tor (on Linux)")
        print("  On Windows: Open Tor Browser, keep it running in background.")
        return

    # Step 2: Try to fetch a known .onion page
    print(f"\n[2] Attempting to scrape: {TEST_ONION_URL}")
    try:
        connector = ProxyConnector.from_url(tor_proxy)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"}
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            async with session.get(TEST_ONION_URL) as resp:
                status = resp.status
                html = await resp.text()
                size_kb = len(html) / 1024
                print(f"    [OK] HTTP Status: {status}")
                print(f"    [OK] Page size: {size_kb:.1f} KB")
                print(f"    [OK] First 200 chars: {html[:200].strip()}")
                print(f"\n  RESULT: .onion scraping IS POSSIBLE via Tor proxy!")
                print(f"  The engine can fetch HTML from .onion sites when Tor is running.")
    except asyncio.TimeoutError:
        print(f"    [TIMEOUT] Site did not respond within 60 seconds.")
        print(f"\n  RESULT: Tor is working but this specific .onion timed out (normal for ransomware sites).")
    except Exception as e:
        print(f"    [FAIL] Could not reach .onion site: {e}")
        print(f"\n  RESULT: Tor is working but .onion scraping failed for this target.")

    # Step 3: Try Playwright-based screenshot
    print("\n[3] Testing Playwright + Tor (headless screenshot engine)...")
    try:
        from playwright.async_api import async_playwright
        import os
        os.makedirs("data/screenshots", exist_ok=True)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                proxy={"server": tor_proxy},
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            page = await context.new_page()
            
            print(f"    Navigating via Playwright+Tor to DuckDuckGo .onion...")
            try:
                response = await page.goto(TEST_ONION_URL, timeout=90000, wait_until="domcontentloaded")
                if response and response.status < 400:
                    title = await page.title()
                    ss_path = "data/screenshots/test_tor_playwright.png"
                    await page.screenshot(path=ss_path, full_page=False)
                    print(f"    [OK] Page title: {title}")
                    print(f"    [OK] Screenshot saved to: {ss_path}")
                    print(f"\n  RESULT: Playwright + Tor screenshot capture is FULLY FUNCTIONAL!")
                else:
                    print(f"    [WARN] HTTP {response.status if response else 'No response'}")
                    print(f"\n  RESULT: Playwright connected via Tor but got error HTTP status.")
            except Exception as e:
                print(f"    [TIMEOUT/FAIL] {e}")
                print(f"\n  RESULT: Playwright+Tor connected but .onion navigation timed out.")
                print(f"  This is NORMAL for ransomware leak sites which are often slow/down.")
            finally:
                await browser.close()
    except Exception as e:
        print(f"    [FAIL] Playwright error: {e}")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    asyncio.run(test_tor_and_scrape())
