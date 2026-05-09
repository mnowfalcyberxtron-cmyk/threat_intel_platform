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
                        self.logger.warning("HTTP %d (Access Denied) from %s — possible bot detection", resp.status, url[:80])
                        return None
                    elif resp.status == 404:
                        self.logger.warning("HTTP 404 (Not Found) from %s", url[:80])
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
                self.logger.error("GET %s: %s", url[:60], e)
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
                        self.logger.warning("HTTP %d from %s", resp.status, url[:80])
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
                 malware_family="", tags=None, confidence="medium",
                 first_seen=None, last_seen=None, description="", raw=None):
        ts = now_iso()
        return {
            "source": source, "type": "ioc",
            "ioc": str(ioc).strip(), "ioc_type": ioc_type,
            "threat_actor": threat_actor or "unknown",
            "malware": malware or "", "malware_family": malware_family or "",
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
