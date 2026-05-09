"""
engine/web_search.py — Free web search for AI context enrichment.
Uses DuckDuckGo (no API key needed) + threat intel site scrapers.
Returns structured results with URL, title, snippet for AI citation.
"""
import asyncio
import logging
import re
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus, urljoin

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger("engine.web_search")

# ── Threat Intelligence specific search endpoints ────────────────────────────
# DuckDuckGo HTML search — free, no key, no rate limit for reasonable use
DDG_URL     = "https://html.duckduckgo.com/html/"
DDG_INSTANT = "https://api.duckduckgo.com/"

# High-value threat intel sources to prioritize in search results
TI_PRIORITY_DOMAINS = [
    "mandiant.com", "crowdstrike.com", "microsoft.com", "secureworks.com",
    "unit42.paloaltonetworks.com", "trendmicro.com", "sentinelone.com",
    "krebsonsecurity.com", "bleepingcomputer.com", "therecord.media",
    "cisa.gov", "nvd.nist.gov", "cert.gov", "sans.org",
    "recordedfuture.com", "sekoia.io", "group-ib.com", "fireeye.com",
    "symantec.com", "kaspersky.com", "eset.com", "checkpoint.com",
    "socradar.io", "threatpost.com", "darkreading.com", "infosecurity-magazine.com",
    "portswigger.net", "rapid7.com", "tenable.com", "qualys.com",
]


def _make_ssl():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return False


async def search_web(
    query: str,
    max_results: int = 8,
    ti_only: bool = False,
) -> List[Dict[str, str]]:
    """
    Search DuckDuckGo for threat intelligence context.
    Returns list of {title, url, snippet, source} dicts.
    """
    # Append site qualifiers for threat-intel-specific search
    if ti_only:
        # Search within known TI sites
        site_q = " OR ".join(f"site:{d}" for d in TI_PRIORITY_DOMAINS[:8])
        full_query = f"{query} ({site_q})"
    else:
        full_query = f"{query} threat intelligence cybersecurity"

    results = await _ddg_search(full_query, max_results)
    if not results:
        # Fallback: plain query
        results = await _ddg_search(query, max_results)

    # Sort: priority TI domains first
    def score(r):
        url = r.get("url", "")
        for i, domain in enumerate(TI_PRIORITY_DOMAINS):
            if domain in url:
                return i
        return 999
    results.sort(key=score)
    return results[:max_results]


async def search_threat_actor(actor: str) -> List[Dict[str, str]]:
    """Search for latest intel on a specific threat actor/group."""
    queries = [
        f'"{actor}" ransomware group 2024 2025 TTPs malware',
        f'"{actor}" threat actor campaign attack analysis',
        f'"{actor}" IOC indicators compromise MITRE',
    ]
    all_results = []
    for q in queries[:2]:
        results = await _ddg_search(q, 5)
        all_results.extend(results)
    # Deduplicate by URL
    seen = set()
    unique = []
    for r in all_results:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)
    return unique[:10]


async def search_malware(malware_name: str) -> List[Dict[str, str]]:
    """Search for latest malware analysis and intel."""
    queries = [
        f'"{malware_name}" malware analysis technical 2024 2025',
        f'"{malware_name}" indicators compromise detection evasion',
    ]
    all_results = []
    for q in queries[:2]:
        r = await _ddg_search(q, 5)
        all_results.extend(r)
    seen = set()
    unique = []
    for r in all_results:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)
    return unique[:8]


async def search_cve(cve_id: str) -> List[Dict[str, str]]:
    """Search for CVE exploitation intel."""
    queries = [
        f"{cve_id} exploit PoC wild exploitation",
        f"{cve_id} vulnerability analysis patch",
    ]
    all_results = []
    for q in queries:
        r = await _ddg_search(q, 4)
        all_results.extend(r)
    return all_results[:8]


async def fetch_page_content(url: str, max_chars: int = 3000) -> Optional[str]:
    """Fetch and extract main text content from a URL."""
    ssl_ctx = _make_ssl()
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        conn    = aiohttp.TCPConnector(ssl=ssl_ctx)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*",
        }
        async with aiohttp.ClientSession(timeout=timeout, connector=conn) as sess:
            async with sess.get(url, headers=headers, allow_redirects=True) as resp:
                if resp.status != 200:
                    return None
                html = await resp.text(errors="replace")
                soup = BeautifulSoup(html, "html.parser")

                # Remove noise
                for tag in soup(["script","style","nav","header","footer",
                                  "aside","form","iframe","noscript"]):
                    tag.decompose()

                # Get main content
                main = (soup.find("article") or soup.find("main") or
                        soup.find("div", class_=re.compile(r"content|post|article|body", re.I)) or
                        soup.find("body"))
                if not main:
                    return None

                text = main.get_text(separator=" ", strip=True)
                # Clean whitespace
                text = re.sub(r"\s+", " ", text).strip()
                return text[:max_chars]
    except Exception as e:
        logger.debug("fetch_page %s: %s", url[:60], e)
        return None


# ── DuckDuckGo HTML scraper ───────────────────────────────────────────────────

async def _ddg_search(query: str, max_results: int = 8) -> List[Dict[str, str]]:
    ssl_ctx = _make_ssl()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://html.duckduckgo.com/",
    }
    results = []
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        conn    = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(timeout=timeout, connector=conn,
                                          headers=headers) as sess:
            # POST to DuckDuckGo HTML search
            async with sess.post(
                DDG_URL,
                data={"q": query, "b": "", "kl": ""},
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         **headers},
            ) as resp:
                if resp.status != 200:
                    return []
                html = await resp.text(errors="replace")

        soup = BeautifulSoup(html, "html.parser")

        # Parse DuckDuckGo HTML results
        for result in soup.find_all("div", class_=re.compile(r"result|web-result", re.I)):
            if len(results) >= max_results:
                break

            # Title + URL
            title_el = (result.find("a", class_=re.compile(r"result__a|result-title", re.I)) or
                        result.find("h2") or result.find("a"))
            if not title_el:
                continue

            title = title_el.get_text(strip=True)
            url   = title_el.get("href", "")

            # DDG wraps URLs — extract real URL
            if "uddg=" in url:
                m = re.search(r"uddg=([^&]+)", url)
                if m:
                    from urllib.parse import unquote
                    url = unquote(m.group(1))
            elif url.startswith("/"):
                url = f"https://duckduckgo.com{url}"

            # Skip ads and DDG internal
            if not url.startswith("http") or "duckduckgo.com" in url:
                continue

            # Snippet
            snip_el = result.find(class_=re.compile(r"result__snippet|snippet|abstract", re.I))
            snippet = snip_el.get_text(strip=True) if snip_el else ""

            # Source domain
            source = re.sub(r"^https?://(www\.)?", "", url).split("/")[0]

            results.append({
                "title":   title[:200],
                "url":     url,
                "snippet": snippet[:400],
                "source":  source,
            })

    except Exception as e:
        logger.debug("DDG search '%s': %s", query[:50], e)

    return results
