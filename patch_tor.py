import re

with open('connectors/onion_monitor.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('def _check_tor_available(self) -> bool:', 
'''def _check_tor_available(self) -> bool:
        if os.getenv("IS_VERCEL", "false").lower() == "true":
            self.tor_proxy = None
            return True''')

text = text.replace('connector = ProxyConnector.from_url(self.tor_proxy, rdns=True)', 
'''connector = ProxyConnector.from_url(self.tor_proxy, rdns=True) if self.tor_proxy else None''')

old_session = '''async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(full_url, headers=headers, allow_redirects=True, ssl=False) as resp:'''
new_session = '''if not self.tor_proxy: full_url = full_url.replace('.onion', '.onion.ly')
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(full_url, headers=headers, allow_redirects=True, ssl=False) as resp:'''
text = text.replace(old_session, new_session)

old_fb_session = '''connector = ProxyConnector.from_url(self.tor_proxy, rdns=True)
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=45)) as session:
                full_url = url if url.startswith("http") else f"http://{url}"
                async with session.get(full_url) as resp:'''
new_fb_session = '''connector = ProxyConnector.from_url(self.tor_proxy, rdns=True) if self.tor_proxy else None
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=45)) as session:
                full_url = url if url.startswith("http") else f"http://{url}"
                if not self.tor_proxy: full_url = full_url.replace('.onion', '.onion.ly')
                async with session.get(full_url) as resp:'''
text = text.replace(old_fb_session, new_fb_session)

# Disable Playwright for targeted scans on Vercel
text = text.replace('''async with async_playwright() as p:
            browser = None
            try:
                browser = await p.chromium.launch(
                    proxy={"server": self.tor_proxy},
                    args=["--no-sandbox", "--disable-setuid-sandbox"]
                )''',
'''if os.getenv("IS_VERCEL", "false").lower() == "true":
            logger.warning("[OnionMonitor] Playwright disabled on Vercel. Falling back to HTTP check.")
            await self._fallback_check(site_id, group, url, old_status)
            return True

        async with async_playwright() as p:
            browser = None
            try:
                browser = await p.chromium.launch(
                    proxy={"server": self.tor_proxy} if self.tor_proxy else None,
                    args=["--no-sandbox", "--disable-setuid-sandbox"]
                )''')

with open('connectors/onion_monitor.py', 'w', encoding='utf-8') as f:
    f.write(text)
print('Patched onion_monitor.py')
