from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

import feedparser

from .. import models
from .base import BaseCollector, RawItem


class RSSCollector(BaseCollector):
    subtype = models.SourceSubtype.RSS

    def fetch(self, source: models.Source) -> Iterable[RawItem]:
        parsed = feedparser.parse(source.url)
        for entry in parsed.entries:
            title = getattr(entry, "title", "").strip()
            link = getattr(entry, "link", "").strip()
            summary = getattr(entry, "summary", "") or getattr(
                entry, "description", ""
            )
            published_at: Optional[datetime] = None
            if getattr(entry, "published_parsed", None):
                published_at = datetime(*entry.published_parsed[:6])
            yield RawItem(
                title=title or link,
                summary_raw=summary or "",
                url=link or source.url,
                published_at_raw=published_at,
                content=summary or "",
            )

