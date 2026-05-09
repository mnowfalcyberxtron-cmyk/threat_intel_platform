from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

import httpx
from bs4 import BeautifulSoup

from .. import models
from .base import BaseCollector, RawItem


class HTMLCollector(BaseCollector):
    subtype = models.SourceSubtype.HTML_PAGE

    def fetch(self, source: models.Source) -> Iterable[RawItem]:
        """
        Generic HTML collector.
        Uses parser_hint as a CSS selector to find advisory items; falls back to links.
        """
        resp = httpx.get(source.url, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        selector = (source.parser_hint or "").strip()
        items = soup.select(selector) if selector else []
        if not items:
            items = soup.find_all("a")

        for el in items:
            text = el.get_text(strip=True)
            href = el.get("href") or source.url
            if not text:
                continue
            url = href if href.startswith("http") else httpx.URL(source.url).join(href)
            yield RawItem(
                title=text,
                summary_raw=text,
                url=str(url),
                published_at_raw=None,
                content=text,
            )

