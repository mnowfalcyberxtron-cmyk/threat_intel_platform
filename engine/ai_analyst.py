"""
engine/ai_analyst.py — CyberXTron AI Analyst
Powered by Claude (Anthropic API) via direct HTTP.
Provides: IOC analysis, threat actor profiling, advisory generation, dark web analysis.
No SDK required — pure aiohttp HTTP calls to api.anthropic.com
"""

import json
import logging
import os
from typing import Any, AsyncGenerator, Dict, List, Optional

import aiohttp

logger = logging.getLogger("engine.ai_analyst")

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-20250514"


class AIAnalyst:
    """
    CyberXTron's embedded AI analyst.
    Wraps Claude API to deliver threat intelligence context,
    IOC analysis, actor profiles, and structured advisories.
    """

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    async def _call(
        self,
        messages: List[Dict],
        system: str = "",
        max_tokens: int = 1200,
        stream: bool = False,
    ) -> str:
        """Direct HTTP call to Anthropic messages API."""
        if not self.api_key:
            return "_AI analysis unavailable — set ANTHROPIC_API_KEY in .env_"

        payload = {
            "model": MODEL,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            payload["system"] = system

        timeout = aiohttp.ClientTimeout(total=60)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.post(
                    ANTHROPIC_API_URL,
                    headers=self._headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        err = await resp.text()
                        logger.error("Anthropic API error %d: %s", resp.status, err[:200])
                        return f"_AI analysis error: HTTP {resp.status}_"
                    data = await resp.json()
                    return data["content"][0]["text"]
        except Exception as e:
            logger.error("AI analyst call failed: %s", e)
            return f"_AI analysis unavailable: {str(e)[:100]}_"

    # ─────────────────────────────────────────────────────────────────────────
    # IOC Analysis
    # ─────────────────────────────────────────────────────────────────────────

    async def analyze_ioc(self, ioc: str, ioc_type: str, context: Dict) -> Dict:
        """
        Deep analysis of a single IOC — returns structured intelligence.
        """
        sources = context.get("sources", [])
        malware = context.get("malware", "")
        threat_actor = context.get("threat_actor", "")
        confidence = context.get("confidence_label", "")
        first_seen = context.get("first_seen", "")
        last_seen = context.get("last_seen", "")
        tags = context.get("tags", [])

        system = """You are a senior threat intelligence analyst at CyberXTron, a cybersecurity firm.
You specialize in IOC analysis, malware attribution, and threat actor tracking.
Provide concise, actionable, structured intelligence — like a Mandiant or CrowdStrike report.
Always respond in valid JSON with no extra text or markdown fences."""

        user_msg = f"""Analyze this IOC and provide structured threat intelligence:

IOC: {ioc}
Type: {ioc_type}
Malware Family: {malware or 'unknown'}
Threat Actor: {threat_actor or 'unknown'}
Confidence: {confidence}
First Seen: {first_seen}
Last Seen: {last_seen}
Sources: {', '.join(sources)}
Tags: {', '.join(tags) if tags else 'none'}

Respond ONLY with this exact JSON structure (no markdown, no extra text):
{{
  "verdict": "malicious|suspicious|unknown",
  "severity": "critical|high|medium|low",
  "summary": "2-3 sentence technical summary of this IOC",
  "threat_context": "What malware/campaign this IOC is associated with and why it matters",
  "attribution": "Threat actor attribution if known, else 'Unknown/unattributed'",
  "behavior": "What this IOC does technically (C2 beacon, payload delivery, data exfil, etc.)",
  "geo_context": "Geographic origin or hosting context if determinable",
  "recommendations": ["action1", "action2", "action3"],
  "mitre_techniques": ["T1071.001", "T1041"],
  "related_malware": ["family1", "family2"],
  "detection_rule": "YARA or Sigma rule hint or keyword for detection",
  "analyst_note": "Additional context, caveats, or hunting tips"
}}"""

        raw = await self._call(
            messages=[{"role": "user", "content": user_msg}],
            system=system,
            max_tokens=1000,
        )

        try:
            result = json.loads(raw)
        except Exception:
            result = {
                "verdict": "unknown",
                "severity": "medium",
                "summary": raw[:300],
                "recommendations": ["Monitor for activity", "Block at perimeter"],
                "analyst_note": "Automated parsing failed — see raw response above",
            }
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Threat Actor Profile
    # ─────────────────────────────────────────────────────────────────────────

    async def profile_threat_actor(
        self, actor_name: str, ioc_count: int, victim_count: int,
        recent_victims: List[Dict], malware_families: List[str],
        targeted_countries: List[str], targeted_industries: List[str],
    ) -> Dict:
        """Generate a comprehensive threat actor intelligence profile."""

        system = """You are a senior CTI analyst at CyberXTron. You write detailed, accurate
threat actor profiles based on open-source intelligence, similar to those published by
CrowdStrike, Mandiant, or Recorded Future. Respond ONLY in valid JSON."""

        victims_str = ", ".join(v.get("victim_name", "") for v in recent_victims[:5])
        malware_str = ", ".join(malware_families[:5]) if malware_families else "unknown"

        user_msg = f"""Generate a threat actor intelligence profile for: {actor_name}

Platform data:
- IOCs attributed: {ioc_count}
- Known victims: {victim_count}
- Recent victims: {victims_str or 'none recorded'}
- Malware used: {malware_str}
- Target countries: {', '.join(targeted_countries[:8]) or 'unknown'}
- Target industries: {', '.join(targeted_industries[:8]) or 'unknown'}

Respond ONLY with this JSON (no markdown, no extra text):
{{
  "actor_name": "{actor_name}",
  "aliases": ["alias1", "alias2"],
  "classification": "ransomware-group|apt|cybercriminal|hacktivst|nation-state",
  "origin": "suspected country/region of origin",
  "active_since": "year or date range",
  "current_status": "active|dormant|defunct|rebranded",
  "motivation": "financial|espionage|disruption|ideological",
  "sophistication": "high|medium|low",
  "summary": "3-4 sentence executive overview of this actor",
  "history": "Key history, major incidents, evolution of the group",
  "ttps": {{
    "initial_access": ["method1", "method2"],
    "execution": ["technique1"],
    "persistence": ["technique1"],
    "lateral_movement": ["technique1"],
    "exfiltration": ["technique1"],
    "impact": ["technique1"]
  }},
  "malware_arsenal": ["tool1", "tool2"],
  "known_vulnerabilities_exploited": ["CVE-xxxx-xxxxx"],
  "mitre_techniques": ["T1190", "T1486", "T1041"],
  "victim_profile": "Description of typical targets",
  "ransom_demands": "Typical ransom range if ransomware group",
  "iocs_indicators": "Types of IOCs typically associated with this actor",
  "intelligence_gaps": "What is unknown about this actor",
  "detection_recommendations": ["rec1", "rec2", "rec3"],
  "threat_level": "critical|high|medium|low",
  "analyst_assessment": "CyberXTron analyst assessment and outlook"
}}"""

        raw = await self._call(
            messages=[{"role": "user", "content": user_msg}],
            system=system,
            max_tokens=1500,
        )

        try:
            return json.loads(raw)
        except Exception:
            return {
                "actor_name": actor_name,
                "summary": raw[:400],
                "threat_level": "unknown",
                "analyst_assessment": "Profile generation encountered a parsing error.",
            }

    # ─────────────────────────────────────────────────────────────────────────
    # Advisory / Report Generation
    # ─────────────────────────────────────────────────────────────────────────

    async def generate_advisory(
        self,
        advisory_type: str,
        context: Dict,
        streaming_callback=None,
    ) -> str:
        """
        Generate a full structured threat advisory / intelligence report.
        advisory_type: 'weekly_summary' | 'threat_actor' | 'malware_analysis' | 'incident_advisory'
        """
        system = """You are a senior threat intelligence analyst at CyberXTron, a Chennai-based
cybersecurity firm. You write professional, actionable threat advisories similar to those
published by CrowdStrike, Mandiant, or CERT-In. Your reports are used by security teams
and executives. Write in clear, professional English. Use proper markdown formatting.
Be specific and technical — not generic. Include real IOC examples from the context provided."""

        prompts = {
            "weekly_summary": self._build_weekly_prompt(context),
            "threat_actor": self._build_actor_prompt(context),
            "malware_analysis": self._build_malware_prompt(context),
            "incident_advisory": self._build_incident_prompt(context),
        }

        user_msg = prompts.get(advisory_type, prompts["weekly_summary"])

        return await self._call(
            messages=[{"role": "user", "content": user_msg}],
            system=system,
            max_tokens=2000,
        )

    def _build_weekly_prompt(self, ctx: Dict) -> str:
        stats = ctx.get("stats", {})
        top_groups = ctx.get("top_groups", [])
        top_actors = ctx.get("top_actors", [])
        recent_victims = ctx.get("recent_victims", [])
        high_conf_iocs = ctx.get("high_conf_iocs", [])
        days = ctx.get("days", 7)

        victims_text = "\n".join(
            f"- {v.get('victim_name','?')} ({v.get('country','?')}, {v.get('group_name','?')})"
            for v in recent_victims[:10]
        )
        ioc_text = "\n".join(
            f"- [{i.get('ioc_type')}] {i.get('ioc','?')} — {i.get('malware','?')} ({i.get('confidence_label','?')} confidence)"
            for i in high_conf_iocs[:15]
        )

        return f"""Write a professional weekly threat intelligence advisory for CyberXTron clients.

PLATFORM DATA (Last {days} days):
- Total IOCs: {stats.get('total_iocs', 0)}
- High-confidence IOCs: {stats.get('high_confidence_iocs', 0)}
- New IOCs (24h): {stats.get('new_iocs_24h', 0)}
- Ransomware victims tracked: {stats.get('total_victims', 0)}
- New victims (24h): {stats.get('new_victims_24h', 0)}

TOP RANSOMWARE GROUPS: {', '.join(g.get('group_name','') for g in top_groups[:8])}

RECENT VICTIMS:
{victims_text or 'None recorded in period'}

HIGH-CONFIDENCE IOCs:
{ioc_text or 'No high-confidence IOCs in period'}

Write a comprehensive advisory with these exact sections:
# CyberXTron Weekly Threat Intelligence Advisory
## Classification: TLP:AMBER | {days}-Day Reporting Window

## Executive Summary
(2-3 paragraphs, suitable for CISO/management)

## Threat Landscape Overview
(Key trends, threat level assessment, notable shifts)

## Ransomware Activity
(Group activity, victim analysis, TTPs observed)

## High-Priority IOCs
(Table format: IOC | Type | Confidence | Threat | Action)

## Critical Vulnerabilities in Active Exploitation
(CVEs being actively exploited, patch urgency)

## Threat Actor Activity
(Notable actor movements, new campaigns)

## Defensive Recommendations
(5-7 specific, actionable items)

## MITRE ATT&CK Coverage
(Key techniques observed this period)

---
*CyberXTron Threat Intelligence | Chennai, India | TLP:AMBER*"""

    def _build_actor_prompt(self, ctx: Dict) -> str:
        actor = ctx.get("threat_actor", "Unknown")
        iocs = ctx.get("iocs", [])
        victims = ctx.get("victims", [])
        malware = ctx.get("malware", [])
        countries = ctx.get("countries", [])
        industries = ctx.get("industries", [])

        ioc_sample = "\n".join(
            f"- [{i.get('ioc_type')}] {i.get('ioc','?')}"
            for i in iocs[:20]
        )
        victim_sample = "\n".join(
            f"- {v.get('victim_name','?')} | {v.get('country','?')} | {v.get('industry','?')}"
            for v in victims[:10]
        )

        return f"""Write a deep threat actor intelligence report for: {actor}

PLATFORM-GATHERED INTELLIGENCE:
IOCs attributed to this actor ({len(iocs)} total):
{ioc_sample or 'None attributed'}

Victims ({len(victims)} total):
{victim_sample or 'None recorded'}

Malware/Tools: {', '.join(malware[:8]) or 'Unknown'}
Target Countries: {', '.join(countries[:10]) or 'Unknown'}
Target Industries: {', '.join(industries[:8]) or 'Unknown'}

Write a comprehensive threat actor intelligence report with:
# Threat Actor Intelligence Report: {actor}
## CyberXTron TIP | Classification: TLP:AMBER

## Actor Overview
(Origins, classification, motivation, current status)

## Technical Profile
(TTPs, malware arsenal, infrastructure patterns)

## Victim Profile
(Who they target, geographic focus, industry sectors)

## Attack Chain / Kill Chain
(Step-by-step attack methodology with MITRE techniques)

## Indicators of Compromise
(Organized table of IOCs with context)

## Infrastructure Analysis
(C2 patterns, hosting, domain patterns if determinable)

## Historical Activity
(Notable past incidents, evolution, rebrand history)

## Threat Assessment
(Current threat level, likely next targets, outlook)

## Detection & Hunting Queries
(Sigma/YARA hints, log queries, behavioral detections)

## Defensive Recommendations
(Specific to this actor's TTPs)

---
*CyberXTron Threat Intelligence | Classification: TLP:AMBER*"""

    def _build_malware_prompt(self, ctx: Dict) -> str:
        malware = ctx.get("malware_family", "Unknown")
        iocs = ctx.get("iocs", [])
        ioc_sample = "\n".join(f"- [{i.get('ioc_type')}] {i.get('ioc','?')}" for i in iocs[:20])

        return f"""Write a malware analysis intelligence report for: {malware}

IOCs associated ({len(iocs)} total):
{ioc_sample or 'None in database'}

Write a technical malware intelligence report with:
# Malware Intelligence Report: {malware}

## Malware Classification
## Technical Behavior & Capabilities
## Infection Chain
## C2 Communication Patterns
## Persistence Mechanisms  
## Defense Evasion Techniques
## IOC Table
## YARA Detection Hints
## MITRE ATT&CK Mapping
## Remediation Steps

*CyberXTron Threat Intelligence | TLP:AMBER*"""

    def _build_incident_prompt(self, ctx: Dict) -> str:
        title = ctx.get("title", "Security Incident")
        details = ctx.get("details", "")
        iocs = ctx.get("iocs", [])
        ioc_sample = "\n".join(f"- [{i.get('ioc_type')}] {i.get('ioc','?')}" for i in iocs[:10])

        return f"""Write an incident threat advisory for: {title}

Details: {details}
Related IOCs:
{ioc_sample or 'None provided'}

Write a threat advisory with:
# Threat Advisory: {title}

## Alert Level & Summary
## Affected Systems / Scope
## Technical Details
## IOCs
## Immediate Actions (within 24h)
## Short-term Remediation (1-7 days)
## Detection Rules
## References

*CyberXTron Threat Intelligence | TLP:AMBER*"""

    # ─────────────────────────────────────────────────────────────────────────
    # Dark Web Analysis
    # ─────────────────────────────────────────────────────────────────────────

    async def analyze_dark_web_post(self, content: str, source: str, group: str) -> Dict:
        """Analyze a dark web leak post and extract structured intelligence."""
        system = """You are a dark web intelligence analyst at CyberXTron.
You analyze ransomware leak site posts, breach forum posts, and dark web marketplace listings.
Extract structured intelligence. Respond ONLY in valid JSON."""

        user_msg = f"""Analyze this dark web content from {source} (Group: {group}):

CONTENT:
{content[:1500]}

Respond ONLY with this JSON:
{{
  "victim_name": "organization name if identifiable",
  "victim_type": "company|government|hospital|individual|unknown",
  "country": "country code or name",
  "industry": "industry sector",
  "data_types": ["passwords", "financial", "PII", "health", "IP"],
  "data_volume": "estimated data volume if mentioned",
  "threat_level": "critical|high|medium|low",
  "ransom_demand": "ransom amount if mentioned",
  "deadline": "deadline if mentioned",
  "iocs_mentioned": ["domain.com", "1.2.3.4"],
  "summary": "2-3 sentence summary of the post",
  "analyst_note": "Key intelligence takeaways"
}}"""

        raw = await self._call(
            messages=[{"role": "user", "content": user_msg}],
            system=system,
            max_tokens=600,
        )
        try:
            return json.loads(raw)
        except Exception:
            return {"summary": raw[:300], "threat_level": "unknown"}
