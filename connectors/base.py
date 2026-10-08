"""
connectors/base.py — Base connector with Windows SSL fix + robust retry.
Key fix: ssl=False for Windows cert issues, certifi fallback.
"""
import asyncio
import logging
import ssl
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

from config import settings

logger = logging.getLogger(__name__)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_ssl_context():
    """
    Create SSL context that works on Windows.
    Windows Python often lacks proper CA bundle — this fixes:
    SSLCertVerificationError: certificate verify failed: unable to get local issuer certificate
    """
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
        return ctx
    except ImportError:
        pass
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return False  # aiohttp will use ssl=False


_SSL_CONTEXT = _make_ssl_context()


class BaseConnector(ABC):
    name: str = "base"
    display_name: str = "Base Connector"
    tier: int = 1

    def __init__(self):
        self.logger = logging.getLogger(f"connector.{self.name}")
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT)
            connector = aiohttp.TCPConnector(ssl=_SSL_CONTEXT)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            )
        return self._session

    async def _get(
        self,
        url: str,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        proxy: Optional[str] = None,
    ) -> Optional[Any]:
        session = await self._get_session()
        
        # Default modern browser headers to avoid 403 blocks
        full_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if headers:
            full_headers.update(headers)

        for attempt in range(settings.MAX_RETRIES):
            try:
                async with session.get(
                    url, headers=full_headers, params=params, proxy=proxy,
                    allow_redirects=True,
                ) as resp:
                    if resp.status == 200:
                        ct = resp.content_type or ""
                        if "json" in ct:
                            return await resp.json(content_type=None)
                        return await resp.text(errors="replace")
                    elif resp.status == 429:
                        wait = 60 * (attempt + 1)
                        self.logger.warning("Rate limited %s — waiting %ds", url[:60], wait)
                        await asyncio.sleep(wait)
                    elif resp.status in (401, 403):
                        self.logger.debug("HTTP %d (Access Denied) from %s — possible bot detection", resp.status, url[:80])
                        return None
                    elif resp.status == 404:
                        self.logger.debug("HTTP 404 (Not Found) from %s", url[:80])
                        return None
                    else:
                        self.logger.warning("HTTP %d from %s", resp.status, url[:80])
                        return None
            except asyncio.TimeoutError:
                self.logger.warning("Timeout %s (attempt %d/%d)", url[:60], attempt+1, settings.MAX_RETRIES)
            except aiohttp.ClientSSLError as e:
                self.logger.warning("SSL error %s: %s — retrying with ssl=False", url[:60], e)
                # Force ssl=False on SSL failure
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT),
                        connector=aiohttp.TCPConnector(ssl=False),
                    ) as s:
                        async with s.get(url, headers=full_headers, params=params) as resp:
                            if resp.status == 200:
                                ct = resp.content_type or ""
                                if "json" in ct:
                                    return await resp.json(content_type=None)
                                return await resp.text(errors="replace")
                except Exception as e2:
                    self.logger.error("SSL fallback failed: %s", e2)
                return None
            except Exception as e:
                self.logger.warning("GET %s: %s", url[:60], e)
            if attempt < settings.MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)
        return None

    async def _post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> Optional[Any]:
        session = await self._get_session()
        for attempt in range(settings.MAX_RETRIES):
            try:
                async with session.post(
                    url, data=data, json=json_data, headers=headers
                ) as resp:
                    if resp.status == 200:
                        return await resp.json(content_type=None)
                    elif resp.status == 429:
                        await asyncio.sleep(60 * (attempt + 1))
                    elif resp.status in (401, 403, 404):
                        self.logger.debug("HTTP %d from %s", resp.status, url[:80])
                        return None
                    else:
                        self.logger.warning("HTTP %d from %s", resp.status, url[:80])
                        return None
            except asyncio.TimeoutError:
                self.logger.warning("Timeout POST %s (attempt %d)", url[:60], attempt+1)
            except aiohttp.ClientSSLError as e:
                self.logger.warning("SSL error POST %s — retrying ssl=False", url[:60])
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT),
                        connector=aiohttp.TCPConnector(ssl=False),
                    ) as s:
                        async with s.post(url, data=data, json=json_data, headers=headers) as resp:
                            if resp.status == 200:
                                return await resp.json(content_type=None)
                except Exception as e2:
                    self.logger.error("SSL fallback POST failed: %s", e2)
                return None
            except Exception as e:
                self.logger.error("POST %s: %s", url[:60], e)
            if attempt < settings.MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)
        return None

    async def _fetch_rss_items(
        self,
        url: str,
        headers: Optional[Dict] = None,
    ) -> List[Dict[str, Any]]:
        import urllib.parse
        import xml.etree.ElementTree as ET
        import re

        # Try direct fetch first
        text = await self._get(url, headers=headers)
        
        # Helper to parse RSS/Atom XML using ElementTree or feedparser
        def parse_xml_items(xml_text: str) -> List[Dict[str, Any]]:
            # Try feedparser first if installed
            try:
                import feedparser
                feed = feedparser.parse(xml_text)
                items = []
                for entry in feed.entries:
                    title = getattr(entry, "title", "")
                    link = getattr(entry, "link", "")
                    summary = getattr(entry, "summary", "") or getattr(entry, "description", "") or ""
                    published = getattr(entry, "published", "")
                    
                    summary_clean = re.sub(r'<[^>]+>', ' ', summary)
                    summary_clean = re.sub(r'\s+', ' ', summary_clean).strip()
                    items.append({
                        "title": str(title),
                        "link": str(link),
                        "summary": summary_clean,
                        "published": str(published),
                    })
                if items:
                    return items
            except Exception:
                pass

            # Fallback to standard ElementTree parsing
            try:
                root = ET.fromstring(xml_text)
            except Exception as e:
                self.logger.debug("XML parse error: %s", e)
                return []
            
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            items = []
            xml_items = root.findall(".//item") + root.findall(".//atom:entry", ns)
            for item in xml_items:
                title = ""
                for tag in ["title"]:
                    child = item.find(tag)
                    if child is not None and child.text:
                        title = child.text.strip()
                        break
                
                link = ""
                for tag in ["link", "atom:link"]:
                    child = item.find(tag, ns) if ":" in tag else item.find(tag)
                    if child is not None:
                        if child.text:
                            link = child.text.strip()
                        elif child.get("href"):
                            link = child.get("href").strip()
                        if link:
                            break
                
                summary = ""
                for tag in ["description", "summary", "content", "atom:summary"]:
                    child = item.find(tag, ns) if ":" in tag else item.find(tag)
                    if child is not None and child.text:
                        summary = child.text.strip()
                        break
                
                pubdate = ""
                for tag in ["pubDate", "published", "updated", "atom:published"]:
                    child = item.find(tag, ns) if ":" in tag else item.find(tag)
                    if child is not None and child.text:
                        pubdate = child.text.strip()
                        break
                
                if title or link:
                    summary_clean = re.sub(r'<[^>]+>', ' ', summary)
                    summary_clean = re.sub(r'\s+', ' ', summary_clean).strip()
                    items.append({
                        "title": title,
                        "link": link,
                        "summary": summary_clean,
                        "published": pubdate,
                    })
            return items

        # Helper to parse JSON from rss2json
        def parse_json_items(data: dict) -> List[Dict[str, Any]]:
            items = []
            for item in data.get("items", []):
                title = item.get("title", "")
                link = item.get("link", "")
                summary = item.get("description", "") or item.get("content", "") or ""
                pubdate = item.get("pubDate", "")
                if title or link:
                    summary_clean = re.sub(r'<[^>]+>', ' ', summary)
                    summary_clean = re.sub(r'\s+', ' ', summary_clean).strip()
                    items.append({
                        "title": str(title),
                        "link": str(link),
                        "summary": summary_clean,
                        "published": str(pubdate),
                    })
            return items

        # 1. Check if direct fetch succeeded
        if text and isinstance(text, str) and text.strip():
            # If it's HTML, direct fetch was likely blocked
            if text.strip().startswith(("<!DOCTYPE html", "<html", "<!doctype html")):
                self.logger.debug("Direct fetch returned HTML instead of XML, likely Cloudflare page")
            else:
                items = parse_xml_items(text)
                if items:
                    return items

        # 2. Try rss2json proxy as primary fallback
        fallback_url = f"https://api.rss2json.com/v1/api.json?rss_url={urllib.parse.quote(url)}"
        self.logger.debug(f"Direct RSS fetch failed or returned HTML for {url}, trying rss2json fallback {fallback_url}")
        resp_data = await self._get(fallback_url, headers=headers)
        if isinstance(resp_data, dict) and resp_data.get("status") == "ok":
            items = parse_json_items(resp_data)
            if items:
                return items
        
        # 3. Try allorigins proxy as backup fallback
        fallback_url2 = f"https://api.allorigins.win/raw?url={urllib.parse.quote(url)}"
        self.logger.debug(f"rss2json failed, trying allorigins fallback {fallback_url2}")
        text2 = await self._get(fallback_url2, headers=headers)
        if text2 and isinstance(text2, str) and text2.strip():
            if not text2.strip().startswith(("<!DOCTYPE html", "<html", "<!doctype html")):
                items = parse_xml_items(text2)
                if items:
                    return items
        
        return []

    @abstractmethod
    async def fetch(self) -> List[Dict[str, Any]]:
        ...

    async def run(self) -> List[Dict[str, Any]]:
        self.logger.info("Running connector: %s", self.display_name)
        try:
            results = await self.fetch()
            self.logger.info("%s returned %d records", self.display_name, len(results))
            return results
        except Exception as e:
            self.logger.error("Connector %s failed: %s", self.name, e, exc_info=True)
            return []
        finally:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None

    @staticmethod
    def make_ioc(source, ioc, ioc_type, threat_actor="unknown", malware="",
                 malware_family="", campaign="", tags=None, confidence="medium",
                 first_seen=None, last_seen=None, description="", raw=None):
        ts = now_iso()
        return {
            "source": source, "type": "ioc",
            "ioc": str(ioc).strip(), "ioc_type": ioc_type,
            "threat_actor": threat_actor or "unknown",
            "malware": malware or "", "malware_family": malware_family or "",
            "campaign": campaign or "",
            "tags": tags or [], "confidence": confidence,
            "first_seen": first_seen or ts, "last_seen": last_seen or ts,
            "description": description, "raw": raw or {},
        }

    @staticmethod
    def make_victim(source, group_name, victim_name, description="", country="",
                    industry="", website="", leak_date="", source_url="",
                    status="published", data_size="", onion_url=""):
        return {
            "source": source, "type": "victim",
            "group_name": group_name, "victim_name": victim_name,
            "description": description, "country": country,
            "industry": industry, "website": website,
            "leak_date": str(leak_date), "discovery_date": now_iso(),
            "source_url": source_url, "status": status, "data_size": data_size,
            "onion_url": onion_url,
        }
