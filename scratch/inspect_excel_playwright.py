import asyncio
from playwright.async_api import async_playwright

async def main():
    print("Launching Playwright...")
    async with async_playwright() as p:
        # Launch browser in headless mode
        browser = await p.chromium.launch(headless=True)
        # Create a browser context with custom viewport
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        page = await context.new_page()
        
        url = "https://1drv.ms/x/c/58897f49075b1bc5/IQCbQQAZ3G0DQ7m06TMh0ECXAeugC9AdA_q_3AWMmc2gyVc?e=oyhDHZ"
        print(f"Navigating to {url}...")
        await page.goto(url, wait_until="networkidle", timeout=60000)
        print("Page loaded. Waiting for 10 seconds for Excel to render sheets...")
        await asyncio.sleep(10)
        
        # Take a screenshot to visualize
        screenshot_path = "scratch/playwright_excel.png"
        await page.screenshot(path=screenshot_path)
        print(f"Screenshot saved to {screenshot_path}")
        
        # Print page title and some HTML structure to see if sheets are loaded
        print("Page title:", await page.title())
        
        # Check sheet tab elements in DOM
        tabs = await page.query_selector_all(".sheet-tab")
        print(f"Found {len(tabs)} sheet tab elements (.sheet-tab)")
        for i, tab in enumerate(tabs):
            print(f"  Tab {i}: {await tab.inner_text()}")
            
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
