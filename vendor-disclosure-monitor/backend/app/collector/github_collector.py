from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

import httpx

from .. import models
from .base import BaseCollector, RawItem


class GitHubCollector(BaseCollector):
    """
    Minimal GitHub Security Advisory collector.
    Expects parser_hint to contain an 'org' name, and queries the public advisories API.
    This is intentionally simple and unauthenticated for local use.
    """

    subtype = models.SourceSubtype.GITHUB

    API_URL = "https://api.github.com/orgs/{org}/security-advisories"

    def fetch(self, source: models.Source) -> Iterable[RawItem]:
        org = (source.parser_hint or "").strip() or None
        if not org:
            return []
        url = self.API_URL.format(org=org)
        resp = httpx.get(url, timeout=20)
        if resp.status_code >= 400:
            return []
        data = resp.json()
        if not isinstance(data, list):
            return []

        for adv in data:
            title = adv.get("summary") or adv.get("ghsa_id") or "GitHub Advisory"
            html_url = adv.get("html_url") or source.url
            summary = adv.get("description") or ""
            published_at_raw: Optional[datetime] = None
            published = adv.get("published_at")
            if isinstance(published, str):
                try:
                    published_at_raw = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except Exception:
                    published_at_raw = None

            yield RawItem(
                title=title,
                summary_raw=summary,
                url=html_url,
                published_at_raw=published_at_raw,
                content=summary,
            )

