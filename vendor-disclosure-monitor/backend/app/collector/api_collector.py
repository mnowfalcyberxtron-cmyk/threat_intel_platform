from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

import httpx

from .. import models
from .base import BaseCollector, RawItem


class APICollector(BaseCollector):
    """
    Generic JSON API collector.
    Expects the endpoint to return a list of objects with at least 'title' and 'url' fields.
    This is a simple baseline and can be customized per-source using parser_hint in the future.
    """

    subtype = models.SourceSubtype.API

    def fetch(self, source: models.Source) -> Iterable[RawItem]:
        resp = httpx.get(source.url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            return []

        for obj in data:
            title = str(obj.get("title", "")).strip()
            url = str(obj.get("url", source.url)).strip()
            summary = str(obj.get("summary", obj.get("description", "")) or "")
            published_at_raw: Optional[datetime] = None
            published = obj.get("published_at") or obj.get("date")
            if isinstance(published, str):
                try:
                    published_at_raw = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except Exception:
                    published_at_raw = None

            yield RawItem(
                title=title or url,
                summary_raw=summary,
                url=url,
                published_at_raw=published_at_raw,
                content=summary,
            )

