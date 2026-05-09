from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

from .. import models


@dataclass
class RawItem:
    title: str
    summary_raw: str
    url: str
    published_at_raw: Optional[datetime]
    content: Optional[str] = None


class BaseCollector:
    """
    Base class for all collectors.
    """

    subtype: str

    def fetch(self, source: models.Source) -> Iterable[RawItem]:
        raise NotImplementedError

