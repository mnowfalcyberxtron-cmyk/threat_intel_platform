import asyncio
from playwright.async_api import async_playwright

async def capture_screenshots():
    out_dir = r"C:\Users\xtronuser\.gemini\antigravity\brain\ce4b8767-d3b3-4ace-b58f-ac6e31e212ed"
    print("Starting playwright...")
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        
        print("Capturing dashboard...")
        await page.goto("http://127.0.0.1:8002/")
        await page.wait_for_timeout(3000)
        await page.screenshot(path=f"{out_dir}\\dashboard_screenshot.png", full_page=False)
        print("Dashboard done.")
        
        print("Capturing Dark Web Manager...")
        await page.click("text=Dark Web Manager")
        await page.wait_for_timeout(3000)
        await page.screenshot(path=f"{out_dir}\\darkweb_screenshot.png", full_page=False)
        print("Dark Web Manager done.")
        
        print("Capturing Intel Alerts...")
        await page.click("text=Intel Alerts")
        await page.wait_for_timeout(3000)
        await page.screenshot(path=f"{out_dir}\\alerts_screenshot.png", full_page=False)
        print("Alerts done.")
        
        await browser.close()
    print("All done.")

if __name__ == "__main__":
    asyncio.run(capture_screenshots())
