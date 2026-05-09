"""api/rl_routes.py — Ransomware.live routes using RansomWatch fallback."""
import json
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger("api.rl")
rl_router = APIRouter(prefix="/api/rl", tags=["Ransomware.live"])

_db = None
_ai = None
_rl = None

def get_db():  return _db
def get_ai():  return _ai
def get_rl():  return _rl


def _valid_victim_name(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n or len(n) < 2:
        return False
    if n in {"?", "-", "--", "n/a", "na", "unknown", "none", "null"}:
        return False
    if all(ch in "?-_. " for ch in n):
        return False
    return True


@rl_router.get("/status")
async def rl_status():
    from config import settings
    return {
        "api_key_set": bool(settings.RANSOMWARE_LIVE_API_KEY),
        "enabled":     settings.ENABLE_RANSOMWARE_API,
        "tier":        "PRO" if settings.ENABLE_RANSOMWARE_API else "public+RansomWatch",
        "fallback":    "RansomWatch GitHub mirror (always available)",
    }


@rl_router.get("/groups")
async def list_groups():
    """Get ransomware groups from RansomWatch GitHub."""
    import aiohttp, ssl
    try:
        import certifi
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ssl_ctx = False

    url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(ssl=ssl_ctx)
        ) as sess:
            async with sess.get(url, headers={"User-Agent":"CyberXTron-TIP/2.2"}) as resp:
                if resp.status == 200:
                    groups = await resp.json(content_type=None)
                    return {"groups": groups if isinstance(groups, list) else [], "count": len(groups) if isinstance(groups, list) else 0}
    except Exception as e:
        logger.error("RansomWatch groups: %s", e)

    # Fallback: get from our DB victims grouped
    db = get_db()
    victims = await db.get_victims(page_size=5000)
    groups_seen = {}
    for v in victims.get("items", []):
        g = v.get("group_name","")
        if g and g != "unknown":
            groups_seen[g] = groups_seen.get(g, 0) + 1
    groups = [{"name": g, "victim_count": c} for g, c in
              sorted(groups_seen.items(), key=lambda x: x[1], reverse=True)]
    return {"groups": groups, "count": len(groups), "source": "local_db"}


@rl_router.get("/group/{group_name}")
async def get_group(group_name: str):
    db = get_db()
    ai = get_ai()
    rl = get_rl()
    profile = await rl.get_group_profile(group_name) if rl else None
    victims_data = await db.get_victims(group_name=group_name, page_size=200)
    victims = victims_data.get("items", [])
    ai_analysis = None
    if ai:
        try: ai_analysis = await ai.analyze_ransomware_group(group_name, victims)
        except Exception as e: logger.debug("AI group: %s", e)
    return {"group_name": group_name, "profile": profile,
            "victim_count": victims_data.get("total", 0),
            "recent_victims": victims[:20], "ai_analysis": ai_analysis}


@rl_router.get("/victims/recent")
async def recent_victims(limit: int = Query(50, ge=1, le=500)):
    # Priority 1: Local DB (contains aggregated data from all sources)
    db = get_db()
    data = await db.get_victims(page_size=limit)
    if data and data.get("items"):
        clean = [v for v in data.get("items", []) if _valid_victim_name(v.get("victim_name", ""))]
        return {"victims": clean, "count": len(clean), "source": "local_db"}

    # Priority 2: Fallback to RansomWatch GitHub mirror
    import aiohttp, ssl
    try:
        import certifi
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ssl_ctx = False

    url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(
            timeout=timeout, connector=aiohttp.TCPConnector(ssl=ssl_ctx)
        ) as sess:
            async with sess.get(url) as resp:
                if resp.status == 200:
                    posts = await resp.json(content_type=None)
                    if isinstance(posts, list):
                        return {"victims": posts[:limit], "count": len(posts[:limit]),
                                "source": "ransomwatch_github"}
    except Exception as e:
        logger.debug("RansomWatch fallback failed: %s", e)

    return {"victims": [], "count": 0, "source": "none"}


@rl_router.get("/victims/search/{query}")
async def search_victims(query: str):
    rl = get_rl()
    db = get_db()
    # Search in local DB first (always works)
    data = await db.get_victims(search=query, page_size=100)
    local_results = data.get("items", [])

    # Also search RansomWatch if available
    rw_results = []
    if rl:
        try: rw_results = await rl.search_victims(query)
        except Exception: pass

    return {"query": query, "results": local_results + rw_results,
            "count": len(local_results) + len(rw_results)}


@rl_router.get("/posts")
async def get_posts(limit: int = Query(100, ge=1, le=1000)):
    rl = get_rl()
    if rl:
        try:
            posts = await rl.get_all_posts(limit=limit)
            if posts: return {"posts": posts, "count": len(posts)}
        except Exception: pass
    db = get_db()
    data = await db.get_victims(page_size=limit)
    return {"posts": data.get("items",[]), "count": data.get("total",0)}


@rl_router.get("/cyberattacks")
async def get_cyberattacks():
    from config import settings
    if not settings.ENABLE_RANSOMWARE_API:
        raise HTTPException(403, "Ransomware.live Pro key required. Set RANSOMWARE_LIVE_API_KEY + ENABLE_RANSOMWARE_API=true")
    rl = get_rl()
    if not rl: raise HTTPException(503, "RL connector not initialized")
    import aiohttp
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(f"{rl.PUBLIC_BASE}/v2/cyberattacks", headers=rl._headers) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    attacks = rl._extract_list(data)
                    return {"attacks": attacks, "count": len(attacks)}
    except Exception as e:
        raise HTTPException(504, f"Ransomware.live API unavailable: {e}")


@rl_router.get("/groups/detailed")
async def list_groups_detailed():
    """Return all groups with full metadata: TTPs, tools, locations (IOCs)."""
    import aiohttp, ssl
    try:
        import certifi
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ssl_ctx = False

    # Ransomware.live public API (no key needed for group list with TTPs)
    url = "https://api.ransomware.live/v2/groups"
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(ssl=ssl_ctx)
        ) as sess:
            async with sess.get(url, headers={"User-Agent": "CyberXTron-TIP/2.4"}) as resp:
                if resp.status == 200:
                    groups = await resp.json(content_type=None)
                    if isinstance(groups, list):
                        # Merge with RansomWatch groups
                        try:
                            rw_url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"
                            async with sess.get(rw_url, headers={"User-Agent": "CyberXTron-TIP/2.4"}) as rw_resp:
                                if rw_resp.status == 200:
                                    rw_groups = await rw_resp.json(content_type=None)
                                    if isinstance(rw_groups, list):
                                        existing_names = {g.get("name", "").lower() for g in groups}
                                        for rwg in rw_groups:
                                            r_name = rwg.get("name", "")
                                            if r_name and r_name.lower() not in existing_names:
                                                groups.append({"name": r_name, "locations": [], "profile": []})
                                                existing_names.add(r_name.lower())
                        except Exception as e:
                            logger.error("Error merging RansomWatch groups: %s", e)

                        # Build local DB evidence map (victim/ioc counts)
                        db = get_db()
                        victim_counts = {}
                        ioc_counts = {}
                        try:
                            async with db._conn.execute(
                                """SELECT LOWER(TRIM(group_name)) AS g, COUNT(*) AS cnt
                                   FROM ransomware_victims
                                   WHERE TRIM(group_name) != '' AND LOWER(TRIM(group_name)) != 'unknown'
                                   GROUP BY LOWER(TRIM(group_name))"""
                            ) as cur:
                                for row in await cur.fetchall():
                                    victim_counts[row[0]] = row[1]

                            async with db._conn.execute(
                                """SELECT LOWER(TRIM(threat_actor)) AS g, COUNT(*) AS cnt
                                   FROM iocs
                                   WHERE TRIM(threat_actor) != '' AND LOWER(TRIM(threat_actor)) != 'unknown'
                                   GROUP BY LOWER(TRIM(threat_actor))"""
                            ) as cur:
                                for row in await cur.fetchall():
                                    ioc_counts[row[0]] = row[1]

                            # Keep local-only groups too (groups with local data but missing from RL/RW lists)
                            existing_names = {g.get("name", "").strip().lower() for g in groups if g.get("name")}
                            for lg in set(victim_counts.keys()) | set(ioc_counts.keys()):
                                if lg and lg not in existing_names:
                                    groups.append({"name": lg, "locations": [], "profile": []})
                                    existing_names.add(lg)
                        except Exception as e:
                            logger.error("Error merging local groups: %s", e)

                        # Attach local evidence counters and filter out empty/no-evidence groups.
                        # This avoids showing actors that exist by name only but have no usable data.
                        filtered = []
                        for g in groups:
                            name = (g.get("name") or "").strip()
                            if not name:
                                continue
                            key = name.lower()
                            vcnt = int(victim_counts.get(key, 0))
                            icnt = int(ioc_counts.get(key, 0))
                            locs = g.get("locations") or []
                            g["victim_count"] = vcnt
                            g["ioc_count"] = icnt
                            g["has_local_data"] = (vcnt + icnt) > 0

                            # UI should prioritize groups that have actual local intelligence.
                            if g["has_local_data"] or len(locs) > 0:
                                filtered.append(g)

                        # Sort groups alphabetically
                        filtered.sort(key=lambda x: x.get("name", "").lower())
                        return {"groups": filtered, "count": len(filtered), "source": "ransomware.live + local + rw"}
    except Exception as e:
        import traceback
        logger.warning("ransomware.live detailed groups: %s", e)
        traceback.print_exc()

    return {"groups": [], "count": 0, "source": "none"}


@rl_router.get("/group/{group_name}/iocs")
async def get_group_iocs(group_name: str):
    """
    Per-group IOC view: network IOCs (onion/clearweb sites from RL),
    known tools, MITRE TTPs, and recent victims from local DB.
    """
    import aiohttp, ssl
    try:
        import certifi
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ssl_ctx = False

    rl_group_data = None
    # Try ransomware.live API for this specific group
    url = f"https://api.ransomware.live/v2/group/{group_name.lower()}"
    try:
        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(ssl=ssl_ctx)
        ) as sess:
            async with sess.get(url, headers={"User-Agent": "CyberXTron-TIP/2.4"}) as resp:
                if resp.status == 200:
                    raw = await resp.json(content_type=None)
                    # API returns a list; pick the matching group
                    if isinstance(raw, list):
                        for g in raw:
                            if (g.get("name", "").lower() == group_name.lower() or
                                    g.get("altname", "").lower() == group_name.lower()):
                                rl_group_data = g
                                break
                        if not rl_group_data and raw:
                            rl_group_data = raw[0]
                    elif isinstance(raw, dict):
                        rl_group_data = raw
    except Exception as e:
        logger.debug("RL group/%s: %s", group_name, e)

    # If direct lookup failed, try all-groups list and search
    if not rl_group_data:
        try:
            url_all = "https://api.ransomware.live/v2/groups"
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=ssl_ctx)
            ) as sess:
                async with sess.get(url_all, headers={"User-Agent": "CyberXTron-TIP/2.4"}) as resp:
                    if resp.status == 200:
                        groups = await resp.json(content_type=None)
                        if isinstance(groups, list):
                            for g in groups:
                                if (g.get("name", "").lower() == group_name.lower() or
                                        (g.get("altname") or "").lower() == group_name.lower()):
                                    rl_group_data = g
                                    break
        except Exception as e:
            logger.debug("RL group search fallback: %s", e)

    # Build structured IOC response
    network_iocs = []
    tools_iocs = []
    ttps_list = []

    if rl_group_data:
        # Onion / clearweb locations → network IOCs
        for loc in rl_group_data.get("locations", []):
            fqdn = loc.get("fqdn", "")
            slug = loc.get("slug", "")
            loc_type = loc.get("type", "DLS")
            available = loc.get("available", False)
            if fqdn:
                network_iocs.append({
                    "ioc": fqdn,
                    "ioc_type": "domain" if not fqdn.endswith(".onion") else "onion",
                    "slug": slug,
                    "site_type": loc_type,
                    "available": available,
                    "title": loc.get("title", ""),
                })

        # Tools → host IOCs
        for tool_obj in rl_group_data.get("tools", []):
            if isinstance(tool_obj, dict):
                for category, tool_list in tool_obj.items():
                    if isinstance(tool_list, list):
                        for t in tool_list:
                            if t:
                                tools_iocs.append({"tool": t, "category": category})
            elif isinstance(tool_obj, str) and tool_obj:
                tools_iocs.append({"tool": tool_obj, "category": "tool"})

        # TTPs
        for tactic in rl_group_data.get("ttps", []):
            tactic_name = tactic.get("tactic_name", "")
            tactic_id = tactic.get("tactic_id", "")
            for tech in tactic.get("techniques", []):
                ttps_list.append({
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_name,
                    "technique_id": tech.get("technique_id", ""),
                    "technique_name": tech.get("technique_name", ""),
                    "details": tech.get("technique_details", ""),
                })

    # Recent victims from local DB
    db = get_db()
    victims_data = await db.get_victims(group_name=group_name, page_size=30)
    victims = [v for v in victims_data.get("items", []) if _valid_victim_name(v.get("victim_name", ""))]

    # Local DB IOCs (scraped IPs, MD5s, etc.) — use group-specific query that returns ALL types
    db_iocs_raw = await db.get_iocs_for_group(threat_actor=group_name, page_size=300)
    db_iocs_data = {"items": db_iocs_raw}
    
    # Lazy-scrape trigger: If we haven't scraped this group's deep IOCs yet (or have very few), do it on the fly!
    scraped_count = sum(1 for i in db_iocs_raw if "scraped" in i.get("tags", ""))
    if scraped_count < 2:
        from connectors.ransomware_live import RansomwareLiveConnector
        import logging
        logging.getLogger("api.rl").info(f"Triggering on-demand deep scrape for {group_name}...")
        try:
            c = RansomwareLiveConnector()
            iocs = await c.scrape_group_iocs(group_name)
            if iocs:
                for ioc in iocs:
                    await db.upsert_ioc(ioc)
                # Ensure newly scraped onions immediately flow to Dark Web Manager
                await db.sync_discovered_onions()
                # Reload IOCs from DB with all types
                db_iocs_raw = await db.get_iocs_for_group(threat_actor=group_name, page_size=300)
                db_iocs_data = {"items": db_iocs_raw}
        except Exception as e:
            logging.getLogger("api.rl").error(f"On-demand scrape failed for {group_name}: {e}")

    for i in db_iocs_data.get("items", []):
        # Always add ALL IOC types from local DB (IPs, Hashes, Domains, Onions)
        if not any(n["ioc"] == i["ioc"] for n in network_iocs):
            tags = i.get("tags", "")
            is_scraped = "scraped" in (tags if isinstance(tags, str) else json.dumps(tags))
            network_iocs.append({
                "ioc": i["ioc"],
                "ioc_type": i.get("ioc_type", "unknown"),
                "slug": "",
                "site_type": "Scraped Intel" if is_scraped else "Local DB",
                "available": True,
                "title": i.get("description", ""),
            })

    # ── Platform Coverage: cross-reference all platform DBs ─────────────────────
    platform_coverage = []
    g_lower = group_name.lower()

    try:
        # 1. Dark Web Manager — onion_sites table
        async with db._conn.execute(
            "SELECT COUNT(*) as c, SUM(CASE WHEN last_status='200' THEN 1 ELSE 0 END) as online FROM onion_sites WHERE LOWER(group_name) LIKE ?",
            (f"%{g_lower}%",)
        ) as cur:
            row = dict(await cur.fetchone())
            if row["c"]:
                platform_coverage.append({
                    "platform": "Dark Web Manager",
                    "icon": "🕸️",
                    "color": "var(--purple)",
                    "count": row["c"],
                    "detail": f"{row['online'] or 0} online .onion sites tracked",
                    "view": "darkweb-mgr"
                })

        # 2. IOC Intelligence — iocs table (exclude pure onion)
        async with db._conn.execute(
            "SELECT COUNT(*) as c, ioc_type FROM iocs WHERE LOWER(threat_actor) LIKE ? AND ioc_type NOT IN ('onion') GROUP BY ioc_type",
            (f"%{g_lower}%",)
        ) as cur:
            ioc_rows = await cur.fetchall()
        if ioc_rows:
            ioc_summary = ", ".join(f"{r['c']} {r['ioc_type'].upper()}" for r in ioc_rows)
            platform_coverage.append({
                "platform": "IOC Intelligence",
                "icon": "🔬",
                "color": "var(--cyan)",
                "count": sum(r["c"] for r in ioc_rows),
                "detail": ioc_summary,
                "view": "ioc"
            })

        # 3. Ransomware.live / Victims DB
        if victims:
            countries = list({v.get("country", "") for v in victims if v.get("country")})[:3]
            platform_coverage.append({
                "platform": "Ransomware.live",
                "icon": "☠️",
                "color": "var(--red)",
                "count": len(victims),
                "detail": f"{', '.join(countries) or 'Global'} victims",
                "view": "ransomware-live"
            })

        # 4. Alerts DB
        async with db._conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE LOWER(title) LIKE ? OR LOWER(description) LIKE ?",
            (f"%{g_lower}%", f"%{g_lower}%")
        ) as cur:
            alert_count = (await cur.fetchone())["c"]
        if alert_count:
            platform_coverage.append({
                "platform": "Intel Alerts",
                "icon": "⚡",
                "color": "var(--yellow)",
                "count": alert_count,
                "detail": f"{alert_count} triggered alerts",
                "view": "alerts"
            })

        # 5. Social / Telegram intel
        async with db._conn.execute(
            "SELECT COUNT(*) as c, platform FROM social_intel WHERE LOWER(content) LIKE ? OR LOWER(entities) LIKE ? GROUP BY platform",
            (f"%{g_lower}%", f"%{g_lower}%")
        ) as cur:
            social_rows = await cur.fetchall()
        if social_rows:
            for sr in social_rows:
                platform_coverage.append({
                    "platform": f"Social Intel ({sr['platform']})",
                    "icon": "📡",
                    "color": "var(--blue)",
                    "count": sr["c"],
                    "detail": f"{sr['c']} mentions on {sr['platform']}",
                    "view": "social"
                })

        # 6. Live Threat Feed
        async with db._conn.execute(
            "SELECT COUNT(*) as c FROM threat_feed WHERE LOWER(title) LIKE ? OR LOWER(entities) LIKE ?",
            (f"%{g_lower}%", f"%{g_lower}%")
        ) as cur:
            feed_count = (await cur.fetchone())["c"]
        if feed_count:
            platform_coverage.append({
                "platform": "Live Threat Feed",
                "icon": "📰",
                "color": "var(--green)",
                "count": feed_count,
                "detail": f"{feed_count} feed items",
                "view": "feed"
            })

    except Exception as e:
        logger.debug("Platform coverage check failed: %s", e)

    return {
        "group_name": group_name,
        "description": rl_group_data.get("description", "") if rl_group_data else "",
        "altname": rl_group_data.get("altname", "") if rl_group_data else "",
        "added_date": rl_group_data.get("added_date", "") if rl_group_data else "",
        "rl_url": rl_group_data.get("url", "") if rl_group_data else "",
        "network_iocs": network_iocs,
        "tools": tools_iocs,
        "ttps": ttps_list,
        "recent_victims": victims[:20],
        "victim_count": len(victims),
        "source": "ransomware.live" if rl_group_data else "local_db_only",
        "platform_coverage": platform_coverage,
    }

