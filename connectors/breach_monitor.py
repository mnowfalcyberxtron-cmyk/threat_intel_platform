"""
connectors/breach_monitor.py — Breach & Leak Site Monitor.
Monitors: HaveIBeenRansom, public breach databases, and data leak intelligence.
No .onion required — uses clearnet endpoints + public APIs.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connectors.base import BaseConnector, now_iso


class HaveIBeenRansomConnector(BaseConnector):
    """
    haveibeenransom.com — tracks ransomware victims using public API.
    FREE, no API key required.
    """
    name = "haveibeenransom"
    display_name = "HaveIBeenRansom.com"
    tier = 1

    API_BASE = "https://api.haveibeenransom.com"

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []

        # Fetch recent victims list
        data = await self._get(f"{self.API_BASE}/api/victims")
        if isinstance(data, list):
            records.extend(self._parse_victims(data))
        elif isinstance(data, dict):
            victims = data.get("data") or data.get("victims") or data.get("results", [])
            records.extend(self._parse_victims(victims))

        # Fallback: ransomlook.io has a great public API
        if not records:
            records.extend(await self._fetch_ransomlook())

        return records

    def _parse_victims(self, victims: list) -> List[Dict[str, Any]]:
        records = []
        for v in victims:
            if not isinstance(v, dict):
                continue
            name = (
                v.get("company_name") or v.get("victim") or
                v.get("organization") or v.get("name") or ""
            ).strip()
            if not name:
                continue
            group = (v.get("group_name") or v.get("gang") or v.get("attacker") or "unknown").strip()
            records.append(self.make_victim(
                source=self.name,
                group_name=group,
                victim_name=name,
                description=v.get("description", "")[:400],
                country=v.get("country", "").upper()[:3],
                industry=v.get("activity") or v.get("sector") or v.get("industry") or "",
                website=v.get("website") or v.get("domain") or "",
                leak_date=str(v.get("published") or v.get("date") or ""),
                source_url=v.get("post_url") or v.get("url") or "",
                status="published",
            ))
        return records

    async def _fetch_ransomlook(self) -> List[Dict[str, Any]]:
        """ransomlook.io — excellent free ransomware tracking API."""
        data = await self._get("https://api.ransomlook.io/api/victims/recent")
        if not isinstance(data, list):
            return []
        records = []
        for v in data[:200]:
            if not isinstance(v, dict):
                continue
            name = (v.get("post_title") or v.get("victim") or "").strip()
            group = (v.get("group_name") or "unknown").strip()
            if not name:
                continue
            records.append(self.make_victim(
                source="ransomlook",
                group_name=group,
                victim_name=name,
                description=v.get("description", "")[:400],
                country=(v.get("country") or "").upper()[:3],
                industry=v.get("activity") or "",
                website=v.get("website") or "",
                leak_date=str(v.get("published") or ""),
                source_url=v.get("post_url") or "",
            ))
        return records


class RansomWatchConnector(BaseConnector):
    """
    ransomwatch.telemetry.ltd — open source ransomware victim tracker.
    Aggregates data from 100+ ransomware group leak sites.
    """
    name = "ransomwatch"
    display_name = "RansomWatch"
    tier = 1

    POSTS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    GROUPS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

    async def fetch(self) -> List[Dict[str, Any]]:
        records = []

        # Fetch victim posts
        posts = await self._get(self.POSTS_URL)
        if isinstance(posts, list):
            # Sort by discovered desc, take recent 300
            sorted_posts = sorted(
                posts, key=lambda x: x.get("discovered", ""), reverse=True
            )[:300]
            for post in sorted_posts:
                name = (post.get("post_title") or "").strip()
                group = (post.get("group_name") or "unknown").strip()
                if not name:
                    continue
                records.append(self.make_victim(
                    source=self.name,
                    group_name=group,
                    victim_name=name,
                    description=post.get("description", "")[:400],
                    leak_date=post.get("published") or post.get("discovered") or "",
                    source_url=post.get("post_url") or "",
                    status="published",
                ))

        # Also get IOCs from group infrastructure
        groups = await self._get(self.GROUPS_URL)
        if isinstance(groups, list):
            records.extend(self._extract_group_iocs(groups))

        return records

    def _extract_group_iocs(self, groups: list) -> List[Dict[str, Any]]:
        iocs = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            group_name = group.get("name", "")
            for loc in group.get("locations", []):
                if not isinstance(loc, dict):
                    continue
                # .onion locations = dark web infrastructure IOCs
                onion = loc.get("fqdn") or loc.get("url") or ""
                if onion and ".onion" in onion:
                    iocs.append(self.make_ioc(
                        source=self.name,
                        ioc=onion,
                        ioc_type="domain",
                        threat_actor=group_name,
                        tags=["ransomware", "leak-site", "onion", group_name.lower()],
                        confidence="high",
                        description=f"Ransomware leak site: {group_name}",
                        raw={"group": group_name, "location": loc},
                    ))
        return iocs


class LeakixConnector(BaseConnector):
    """
    leakix.net — public breach and exposed service intelligence.
    Tracks leaked databases, exposed services, and breach indicators.
    """
    name = "leakix"
    display_name = "LeakIX"
    tier = 1

    EVENTS_URL = "https://leakix.net/api/events"

    async def fetch(self) -> List[Dict[str, Any]]:
        # LeakIX requires auth for full access, but events feed is partially open
        data = await self._get(
            self.EVENTS_URL,
            headers={"Accept": "application/json"},
        )
        if not isinstance(data, list):
            return []

        records = []
        for event in data[:100]:
            if not isinstance(event, dict):
                continue
            ip = event.get("ip", "")
            host = event.get("host", "")
            plugin = event.get("event_source", "")
            summary = event.get("summary", "")
            timestamp = event.get("time", now_iso())

            if ip:
                records.append(self.make_ioc(
                    source=self.name,
                    ioc=ip,
                    ioc_type="ip",
                    tags=["exposed-service", "leakix", plugin.lower() if plugin else ""],
                    confidence="medium",
                    first_seen=timestamp,
                    last_seen=timestamp,
                    description=f"LeakIX: {plugin} | {summary[:100]}",
                    raw=event,
                ))
        return records
