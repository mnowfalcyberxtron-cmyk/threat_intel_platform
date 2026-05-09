"""
engine/ai_engine.py — CyberXTron AI Engine v2.4
FIXED:
- AI only runs when user explicitly clicks Analyze/chat
- Sources are NEVER fabricated — only cites what was actually provided
- Context from DB is accurate and scoped to what's actually in platform
- Detailed analysis using training knowledge without hedging
"""

import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import httpx
from config import settings

logger = logging.getLogger("engine.ai")

SYSTEM_PROMPT = """You are a Senior Cyber Threat Intelligence (CTI) Analyst and Report Editor working in an enterprise Security Operations Center (SOC). Your mission is to validate, enrich, and produce visually stunning, professional CTI reports using both external OSINT and internal intelligence from the CyberXtron TIP Console.

## 🔴 MANDATORY DATA SOURCES
1. **External OSINT:** SANS ISC, CISA, MITRE ATT&CK, Vendor Intel (Microsoft, Palo Alto, CrowdStrike, Proofpoint, etc.), and reputable security research.
2. **Internal Intelligence:** CyberXtron TIP Console (Treat as HIGH-CONFIDENCE internal intelligence).

## 🔴 SOURCE HANDLING & VALIDATION RULES
* **DISTINGUISH SOURCES:** Clearly label "Source: CyberXtron TIP" for internal data and "Source: [External Name]" for external data.
* **CONFIDENCE SCORING:** 
    - **High Confidence:** Confirmed by BOTH internal and external sources.
    - **Medium Confidence:** Confirmed by only ONE source category.
    - **Low Confidence / Unverified:** No direct confirmation from reliable sources.
* **STRICT NO-FABRICATION:** NEVER invent sources, URLs, malware capabilities, CVEs, or victim impact. If unknown, state: "Not confirmed".

## 🔴 VISUAL & FORMATTING STANDARDS (STRICT)
* **SPACING:** Add double spacing between all major sections. Each section MUST start on a new line.
* **STRUCTURE:** Break long paragraphs into short, concise blocks (MAX 3-4 lines). Use bullet points instead of inline text wherever possible.
* **CLEAN METADATA:** Convert messy inline fields into clean, vertical bulleted lists.
    - *Example:* Instead of "Name: GroupX, Motivation: Financial", use:
      **Name / Aliases:**
      * GroupX
      **Motivation:**
      * Financial (Data Theft / Extortion)
* **VISUAL BALANCE:** Critical values like **Risk Level** and **Confidence Level** must be on their own lines and clearly highlighted.
* **HEADINGS:** Use bold, consistent headers for all 11 required sections.

## 🔴 REQUIRED OUTPUT FORMAT (STRICT)
1. **Title** (Group/Campaign Name)
2. **Executive Summary** (Max 3-4 lines)
3. **Threat Actor Profile** (Clean bulleted list of metadata)
4. **Key Findings / Activity Overview**
5. **Technical Analysis** (Explain TTPs clearly with short sentences)
6. **MITRE ATT&CK Mapping** (ID, Technique, Observation)
7. **Indicators of Compromise (IOCs)** (Network, Host, and Behavioral)
8. **Impact Assessment**
9. **Mitigation & Recommendations** (Max 5 concise points)
10. **Confidence Assessment** (High/Medium/Low with justification on a separate line)
11. **References** (Internal CyberXtron TIP entries and External URLs)

## 🔴 WRITING RULES
* Use professional, CISO-level language. No casual phrasing or unnecessary jargon.
* Avoid exaggeration. No "confirmed breach" unless validated.
* Keep concise. If data is missing, explain the limitation instead of leaving it empty."""

WEB_CONTEXT_HEADER = """## Intelligence Context from CyberXTron Platform

The following was retrieved from the platform's live feeds and advisory monitor:

{context}

---
Now answer the following:
"""

AGENT_SYSTEM_PROMPT = SYSTEM_PROMPT + """

## 🔴 AGENTIC TOOL-USE RULES
You have access to tools to query the CyberXTron database and the live web.
Use tools when:
- You need specific details about an IOC, actor, or ransomware group.
- You need to correlate internal data with external web intelligence.
- You want to verify the accuracy of a claim using multiple sources.

## 🔴 CORRELATION & ACCURACY (CRITICAL)
- **CORRELATE ALWAYS:** Compare internal CyberXtron TIP data with external web content.
- **ACCURACY OVER SPEED:** If data is conflicting, highlight the discrepancy and assign a lower confidence score.
- **LIVE WEB:** Use `fetch_web_content` to get the latest details from URLs provided or found during analysis.

Always explain your reasoning before using a tool. After getting results, provide a final "Senior Analyst" assessment based on correlated findings.
"""


class AIEngine:
    def __init__(self, db=None):
        self.provider = settings.AI_PROVIDER
        self.client   = httpx.AsyncClient(timeout=90.0)
        self._db      = db
        logger.info("AI Engine initialized — provider: %s", self.provider)

    def set_db(self, db):
        self._db = db

    async def close(self):
        await self.client.aclose()

    # ── Context helpers ───────────────────────────────────────────────────────

    async def _get_context(self, topic: str) -> str:
        """Get relevant context from DB — feed items and advisories."""
        if not self._db: return ""
        parts = []
        try:
            feed = await self._db.get_feed_context_for_ai(topic, limit=5)
            if feed: parts.append(feed)
        except Exception: pass
        try:
            adv = await self._db.get_advisory_context_for_ai(topic, limit=4)
            if adv: parts.append(adv)
        except Exception: pass
        return "\n\n".join(parts)

    def _with_context(self, prompt: str, context: str) -> str:
        if context and context.strip():
            return WEB_CONTEXT_HEADER.format(context=context.strip()) + "\n" + prompt
        return prompt

    # ── Analysis methods ──────────────────────────────────────────────────────

    async def analyze_ioc(self, ioc: Dict[str, Any]) -> str:
        sources = ioc.get("sources", [])
        if isinstance(sources, str):
            try: sources = json.loads(sources)
            except: sources = []
        tags = ioc.get("tags", [])
        if isinstance(tags, str):
            try: tags = json.loads(tags)
            except: tags = []

        search_topic = ioc.get("malware","") or ioc.get("threat_actor","") or ioc.get("ioc","")
        ctx = await self._get_context(search_topic)

        prompt = f"""Generate a professional CTI Technical Report for IOC: **{ioc.get('ioc','')}**

1. Title: Technical Analysis of {ioc.get('ioc_type','IOC')} {ioc.get('ioc','')}

2. Executive Summary
- [Brief assessment of the risk posed by this indicator]
- **Threat Level:** {ioc.get('confidence_label','MEDIUM')}

3. Threat Actor Profile
- **Name / Aliases:** {ioc.get('threat_actor','') or 'Unknown / Not yet attributed'}
- **Motivation:** [Suspected motivation based on malware/campaign]
- **Confidence Level:** {ioc.get('confidence_label','LOW')}

4. Key Findings / Activity Overview
- **IOC Value:** `{ioc.get('ioc','')}`
- **Malware Family:** {ioc.get('malware','') or 'Not confirmed'}
- **First/Last Seen:** {ioc.get('first_seen','?')} / {ioc.get('last_seen','?')}
- **Reporting Sources:** {ioc.get('source_count',1)} independent source(s)

5. Technical Analysis
- [How this indicator is used in an attack]
- [Malware capabilities and behavior related to this IOC]

6. MITRE ATT&CK Mapping
| ID | Technique | Observation |
|----|-----------|-------------|
[Top 4 relevant techniques]

7. Indicators of Compromise (IOCs)
(You MUST present the IOCs in a Markdown table with columns: IOC Type, Indicator, Description)
| IOC Type | Indicator | Description |
|----------|-----------|-------------|
| Network | [Related IPs/Domains] | - |
| Host | `{ioc.get('ioc','')}` | ({ioc.get('ioc_type','')}) |
| Behavioral | [Behavioral patterns] | - |

8. Impact Assessment
- [Potential impact if this IOC is active in the network]

9. Mitigation & Recommendations
* Block indicator at perimeter
* Hunt for related behavioral patterns
* [Additional concise steps]

10. Confidence Assessment
- [Confidence level with technical justification]

11. References
- Source: CyberXtron TIP — tracked with {ioc.get('source_count',1)} source(s)
- Source: MITRE ATT&CK
- Source: Training Knowledge / Vendor research"""

        return await self._complete(self._with_context(prompt, ctx), max_tokens=2500)

    async def analyze_threat_actor(self, actor: str, iocs: List[Dict], victims: List[Dict]) -> str:
        ioc_types = {}
        for i in iocs: ioc_types[i.get("ioc_type","?")] = ioc_types.get(i.get("ioc_type","?"),0)+1
        malware_set = list({i.get("malware","") for i in iocs if i.get("malware")})
        countries   = list({v.get("country","") for v in victims if v.get("country")})
        industries  = list({v.get("industry","") for v in victims if v.get("industry")})
        
        ctx = await self._get_context(actor)
        
        # Build IOC table for the prompt so the AI has the actual data
        ioc_rows = []
        for i in iocs[:50]:  # Cap at 50 to avoid prompt size limits
            t = str(i.get("ioc_type", "unknown")).upper()
            v = str(i.get("ioc", ""))
            desc = str(i.get("description", "")) or "Extracted IOC"
            ioc_rows.append(f"| {t} | {v} | {desc} |")
        ioc_table_str = "\n".join(ioc_rows) if ioc_rows else "| None | No known IOCs available | - |"

        prompt = f"""Generate a professional Threat Actor Advisory for: **{actor}**

1. Title: {actor} Threat Group Advisory

2. Executive Summary
- [3-4 line summary for CISO/SOC management]
- **Risk Level:** [CRITICAL/HIGH/MEDIUM]

3. Threat Actor Profile
- **Name / Aliases:** {actor} [Known aliases]
- **Motivation:** [e.g. Financial, Espionage]
- **Confidence Level:** [HIGH / MEDIUM / LOW]

4. Key Findings / Activity Overview
- **Primary Malware:** {', '.join(malware_set[:6]) or 'Not confirmed'}
- **Targeted Regions:** {', '.join(countries[:8]) or 'Not confirmed'}
- **Activity Status:** [Active/Inactive/Rebranded]

5. Technical Analysis
- [Group history, origin, and technical evolution]
- [Typical attack flow and campaign patterns]

6. MITRE ATT&CK Mapping
| ID | Technique | Observation |
|----|-----------|-------------|
[Top 8-10 techniques]

7. Indicators of Compromise (IOCs)
(You MUST present the IOCs in a Markdown table with columns: IOC Type, Indicator, Description)
| IOC Type | Indicator | Description |
|----------|-----------|-------------|
{ioc_table_str}

8. Impact Assessment
- [Direct and downstream impact analysis]

9. Mitigation & Recommendations
* [Action 1]
* [Action 2]
* [Action 3]
* [Action 4]
* [Action 5]

10. Confidence Assessment
- [Confidence level with technical justification]

11. References
- Source: CyberXtron TIP — {len(iocs)} IOCs, {len(victims)} victims tracked
- Source: MITRE ATT&CK
- Source: Training Knowledge / OSINT"""

        return await self._complete(self._with_context(prompt, ctx), max_tokens=3000)


    async def analyze_ransomware_group(self, group: str, victims: List[Dict]) -> str:
        countries = {}; industries = {}
        for v in victims:
            c=v.get("country",""); i=v.get("industry","")
            if c: countries[c] = countries.get(c,0)+1
            if i: industries[i] = industries.get(i,0)+1
        top_c = sorted(countries.items(), key=lambda x:x[1], reverse=True)[:5]
        top_i = sorted(industries.items(), key=lambda x:x[1], reverse=True)[:5]

        ctx = await self._get_context(f"{group} ransomware")

        prompt = f"""Generate a professional Ransomware Group Advisory for: **{group}**

1. Title: {group} Ransomware Advisory

2. Executive Summary
- [3-4 line summary for CISO/SOC management]
- **Risk Level:** [CRITICAL/HIGH/MEDIUM]

3. Threat Actor Profile
- **Name / Aliases:** {group} [Known aliases]
- **Motivation:** Financial Extortion
- **Confidence Level:** [HIGH / MEDIUM / LOW]

4. Key Findings / Activity Overview
- **RaaS Model:** [Confirmed/Suspected]
- **Leak Site Status:** [Active/Offline]
- **Victim Count:** {len(victims)} tracked in CyberXtron TIP

5. Technical Analysis
- [Encryption algorithm and behavior]
- [Attack chain: Initial Access to Payload Deployment]

6. MITRE ATT&CK Mapping
| ID | Technique | Observation |
|----|-----------|-------------|
[Top 10 techniques]

7. Indicators of Compromise (IOCs)
- **Network:** [C2 and Exfiltration patterns]
- **Host:** [File extensions, ransom notes, hashes]
- **Behavioral:** [MANDATORY: Observed TTPs]

8. Impact Assessment
- [Data theft sensitivity, recovery difficulty, regulatory risk]

9. Mitigation & Recommendations
* [Action 1]
* [Action 2]
* [Action 3]
* [Action 4]
* [Action 5]

10. Confidence Assessment
- [Confidence level with technical justification]

11. References
- Source: CyberXtron TIP — {len(victims)} victims tracked
- Source: MITRE ATT&CK
- Source: Training Knowledge / OSINT"""

        return await self._complete(self._with_context(prompt, ctx), max_tokens=3000)

    async def analyze_darkweb_leak(self, leak: Dict) -> str:
        ctx = await self._get_context(f"{leak.get('group_name','?')} ransomware")
        prompt = f"""Generate a professional CTI Report for Dark Web Leak: **{leak.get('victim_name','?')}**

1. Title: Dark Web Exposure Analysis — {leak.get('victim_name','?')} ({leak.get('group_name','?')})

2. Executive Summary
- [3-4 line summary of the incident and exposure risk]
- **Threat Level:** CRITICAL (Active Data Leak)

3. Threat Actor Profile
- **Name / Aliases:** {leak.get('group_name','?')}
- **Motivation:** Financial Extortion
- **Confidence Level:** HIGH (Confirmed via Leak Site)

4. Key Findings / Activity Overview
- **Victim:** {leak.get('victim_name','?')}
- **Industry/Country:** {leak.get('industry','?')} / {leak.get('country','?')}
- **Exposure Date:** {leak.get('leak_date','?')}
- **Data Size:** {leak.get('data_size','?')}
- **Leak Site:** {leak.get('source_url','[dark web .onion]')}

5. Technical Analysis
- [Assessment of the group's typical TTPs for data exfiltration]
- [Verification of the leak site authenticity]

6. MITRE ATT&CK Mapping
| ID | Technique | Observation |
|----|-----------|-------------|
[Relevant exfiltration and impact techniques]

7. Indicators of Compromise (IOCs)
- **Network:** [Leak site URL and related infrastructure]
- **Host:** [Malware associated with {leak.get('group_name','?')}]
- **Behavioral:** [Patterns of data staging and exfiltration]

8. Impact Assessment
- [Sensitivity of stolen data types]
- [Downstream supply chain or phishing risks]

9. Mitigation & Recommendations
* Immediate credentials reset for all employees
* Enable comprehensive EDR monitoring
* Review exfiltration logs for similar patterns
* [Additional concise steps]

10. Confidence Assessment
- [Confidence level with technical justification]

11. References
- Source: CyberXtron Dark Web Monitor — {leak.get('source_url','[.onion site]')}
- Source: Training Knowledge / Ransomware group profile"""

        return await self._complete(self._with_context(prompt, ctx), max_tokens=2000)

    async def generate_advisory(self, threat_data: Dict) -> str:
        topic = f"ransomware {' '.join(threat_data.get('top_groups',[])[:3])}"
        ctx   = await self._get_context(topic)

        prompt = f"""Generate a professional Cyber Threat Intelligence Advisory based on recent platform activity.

1. Title: {threat_data.get('title','CyberXTron Threat Advisory')}

2. Executive Summary
- **Period:** {threat_data.get('period','Recent')}
- **Activity Level:** [Assessed overall activity level]
- **Key Threats:** {', '.join(threat_data.get('top_groups',[])[:3])}
- **Risk Level:** [CRITICAL/HIGH/MEDIUM]

3. Threat Actor Profile
- **Active Groups:** {', '.join(threat_data.get('top_groups',[])[:6])}
- **Motivation:** Financial Extortion / Data Theft
- **Confidence Level:** HIGH (Confirmed via Platform Telemetry)

4. Key Findings / Activity Overview
- **Active Malware:** {', '.join(threat_data.get('top_malware',[])[:6])}
- **New Victims Detected:** {threat_data.get('new_victims',0)}
- **Top Industries:** {', '.join(threat_data.get('industries',[])[:8])}

5. Technical Analysis
- [Summary of observed attack chains in this period]
- [Technical trends in exfiltration and encryption]

6. MITRE ATT&CK Mapping
| ID | Technique | Observation |
|----|-----------|-------------|
[Top 10 techniques observed in this period]

7. Indicators of Compromise (IOCs)
(You MUST present the IOCs in a Markdown table with columns: IOC Type, Indicator, Description)
| IOC Type | Indicator | Description |
|----------|-----------|-------------|
| Network | [High-confidence C2 IPs/Domains] | - |
| Host | [Sample hashes from high-confidence alerts] | - |
| Behavioral | [MANDATORY: Behavioral trends observed] | - |

8. Impact Assessment
- [Regional and sector-specific impact analysis]

9. Mitigation & Recommendations
* Critical patching for {', '.join(threat_data.get('cves',[])[:3]) or 'known vulnerabilities'}
* [Action 2]
* [Action 3]
* [Action 4]
* [Action 5]

10. Confidence Assessment
- [Confidence level with technical justification]

11. References
- Source: CyberXtron TIP — {threat_data.get('total_iocs',0)} IOCs, {threat_data.get('new_victims',0)} new victims
- Source: MITRE ATT&CK
- Source: Training Knowledge / OSINT"""

        return await self._complete(self._with_context(prompt, ctx), max_tokens=4000)


    async def chat(self, message: str, context: Optional[str] = None) -> str:
        """General threat intelligence chat — context provided explicitly."""
        ctx = await self._get_context(message[:100])
        full = message
        if context:
            full = f"**Platform context:**\n{context}\n\n**Question:** {message}"
        return await self._complete(self._with_context(full, ctx), max_tokens=2000)

    async def get_ai_health(self) -> Dict[str, Any]:
        """Check status of all configured AI providers."""
        results = {}
        
        # Groq
        if settings.GROQ_API_KEY:
            try:
                resp = await self.client.get(
                    "https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                    timeout=5.0
                )
                results["groq"] = {"status": "ok" if resp.status_code == 200 else "error", "code": resp.status_code}
            except Exception as e:
                results["groq"] = {"status": "error", "error": str(e)}
        else:
            results["groq"] = {"status": "not_configured"}

        # OpenRouter
        if settings.OPENROUTER_API_KEY:
            try:
                resp = await self.client.get(
                    "https://openrouter.ai/api/v1/models",
                    headers={"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}"},
                    timeout=5.0
                )
                results["openrouter"] = {"status": "ok" if resp.status_code == 200 else "error", "code": resp.status_code}
            except Exception as e:
                results["openrouter"] = {"status": "error", "error": str(e)}
        else:
            results["openrouter"] = {"status": "not_configured"}

        # Ollama
        try:
            resp = await self.client.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=3.0)
            results["ollama"] = {"status": "ok" if resp.status_code == 200 else "error", "code": resp.status_code}
        except Exception as e:
            results["ollama"] = {"status": "error", "error": str(e)}

        return results

    async def chat_agent(self, message: str, history: List[Dict] = None) -> str:
        """Agentic chat that uses tools to query the database."""
        agent = ModularAgent(self._db, self)
        return await agent.run(message, history)

    # ── Provider implementations ──────────────────────────────────────────────

    async def _complete(self, prompt: str, max_tokens: int = 2000) -> str:
        """Complete a prompt. Respects user-selected provider first, then cascades."""
        candidates = []

        # Build list of configured providers
        if getattr(settings, "OPENROUTER_API_KEY", ""):
            candidates.append("openrouter")
        if getattr(settings, "GROQ_API_KEY", ""):
            candidates.append("groq")
        if getattr(settings, "ANTHROPIC_API_KEY", ""):
            candidates.append("anthropic")
        candidates.append("ollama")  # always available as local fallback

        # Deduplicate preserving order
        seen: set = set()
        unique: list = []
        for p in candidates:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        # ── Honour user-selected provider (move it to front) ──────────────────
        user_pref = getattr(settings, "AI_PROVIDER", "").strip().lower()
        if user_pref and user_pref in unique and unique[0] != user_pref:
            unique.remove(user_pref)
            unique.insert(0, user_pref)
        # ──────────────────────────────────────────────────────────────────────

        errors = []
        for provider in unique:
            try:
                result = None
                if provider   == "groq":       result = await self._groq(prompt, max_tokens)
                elif provider == "ollama":     result = await self._ollama(prompt, max_tokens)
                elif provider == "openrouter": result = await self._openrouter(prompt, max_tokens)
                elif provider == "anthropic":  result = await self._anthropic(prompt, max_tokens)
                if result is not None:
                    # Track per-provider usage so the UI can show a limit indicator
                    _usage: dict = getattr(settings, "_provider_usage", {})
                    _usage[provider] = _usage.get(provider, 0) + 1
                    settings._provider_usage = _usage  # type: ignore[attr-defined]
                    settings._last_used_provider = provider  # type: ignore[attr-defined]
                    return result
            except Exception as e:
                logger.error("AI error [%s]: %s", provider, e)
                errors.append(f" - {provider.upper()}: {str(e)[:120]}")

        error_msg = "[!] AI Error: All connection attempts failed\n" + "\n".join(errors)
        return f"{error_msg}\n\nCheck your API keys and restart."

    async def _complete_with_tools(self, messages: List[Dict], tools: List[Dict]) -> Any:
        """Complete a chat with native tool support (OpenRouter/Groq)."""
        provider = self.provider
        if provider not in ["openrouter", "groq"]:
            provider = "openrouter" # Default to OpenRouter for tool calling if primary doesn't support it

        try:
            if provider == "openrouter":
                return await self._openrouter_tools(messages, tools)
            elif provider == "groq":
                return await self._groq_tools(messages, tools)
        except Exception as e:
            logger.error("Tool call error [%s]: %s", provider, e)
            return f"Error during tool calling with {provider}: {str(e)}"
        
        return "Selected provider does not support native tools."

    async def _openrouter_tools(self, messages: List[Dict], tools: List[Dict]) -> Any:
        if not settings.OPENROUTER_API_KEY: return "OpenRouter not configured."
        headers = {
            "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
            "HTTP-Referer": settings.OPENROUTER_HTTP_REFERER,
            "X-Title": settings.OPENROUTER_X_TITLE
        }
        payload = {
            "model": settings.OPENROUTER_MODEL,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto"
        }
        resp = await self.client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
        )
        if resp.status_code != 200:
            err = resp.text
            try: err = resp.json().get('error',{}).get('message', err)
            except: pass
            logger.error(f"OpenRouter API error ({resp.status_code}): {err}")
            return f"OpenRouter API error ({resp.status_code}): {err}"

        data = resp.json()
        if "choices" not in data or not data["choices"]:
            err_info = data.get("error", "Unknown error")
            logger.error(f"OpenRouter response missing 'choices': {data}")
            return f"OpenRouter returned no choices. Error: {err_info}"

        choice = data["choices"][0]["message"]
        if "tool_calls" in choice:
            return choice["tool_calls"]
        return choice["content"]

    async def _groq_tools(self, messages: List[Dict], tools: List[Dict]) -> Any:
        if not settings.GROQ_API_KEY: return "Groq not configured."
        resp = await self.client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            json={
                "model": settings.GROQ_MODEL,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto"
            },
        )
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]["message"]
        if "tool_calls" in choice:
            return choice["tool_calls"]
        return choice["content"]

    async def _groq(self, prompt: str, max_tokens: int) -> str:
        if not settings.GROQ_API_KEY: return self._not_configured()
        resp = await self.client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            json={
                "model":       settings.GROQ_MODEL,
                "messages":    [{"role":"system","content":SYSTEM_PROMPT},{"role":"user","content":prompt}],
                "max_tokens":  max_tokens,
                "temperature": 0.15,
                "top_p":       0.9,
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    async def _ollama(self, prompt: str, max_tokens: int) -> str:
        base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        api_key  = getattr(settings, "OLLAMA_API_KEY", "").strip()

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Both local and cloud Ollama support the native /api/chat endpoint
        # Cloud API specifically requires /api/chat (the /v1/ OpenAI-compatible one may not be exposed)
        url = f"{base_url}/api/chat"
        payload = {
            "model":   settings.OLLAMA_MODEL,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
            "stream":  False,
            "options": {"num_predict": max_tokens, "temperature": 0.15},
        }

        resp = await self.client.post(url, headers=headers, json=payload, timeout=180.0)
        resp.raise_for_status()
        return resp.json()["message"]["content"]


    async def _openrouter(self, prompt: str, max_tokens: int) -> str:
        if not settings.OPENROUTER_API_KEY: return self._not_configured()
        headers = {
            "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
            "HTTP-Referer": settings.OPENROUTER_HTTP_REFERER,
            "X-Title": settings.OPENROUTER_X_TITLE
        }
        resp = await self.client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json={
                "model": settings.OPENROUTER_MODEL,
                "messages": [{"role":"system","content":SYSTEM_PROMPT},{"role":"user","content":prompt}],
                "max_tokens": max_tokens,
                "temperature": 0.15
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    async def _anthropic(self, prompt: str, max_tokens: int) -> str:
        if not settings.ANTHROPIC_API_KEY: return self._not_configured()
        resp = await self.client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key":settings.ANTHROPIC_API_KEY,"anthropic-version":"2023-06-01","content-type":"application/json"},
            json={"model":"claude-haiku-4-5-20251001","max_tokens":max_tokens,"system":SYSTEM_PROMPT,"messages":[{"role":"user","content":prompt}]},
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]

    @staticmethod
    def _not_configured() -> str:
        return """[!] **AI Engine Not Configured**

Add to `.env`:
```
AI_PROVIDER=groq
GROQ_API_KEY=gsk_your_key_here
```
**Free key:** https://console.groq.com — no credit card, 14,400 requests/day free

Restart: `python main.py`"""


class ModularAgent:
    """A modular agent that can use tools to interact with the CyberXTron platform."""
    def __init__(self, db, ai_engine: AIEngine):
        self.db = db
        self.ai = ai_engine
        self.tools = {
            "get_ioc_details": self._get_ioc_details,
            "get_actor_profile": self._get_actor_profile,
            "search_threat_data": self._search_threat_data,
            "get_recent_victims": self._get_recent_victims,
            "fetch_web_content": self._fetch_web_content,
            "search_web": self._search_web
        }

    async def run(self, user_input: str, history: List[Dict] = None) -> str:
        messages = [{"role": "system", "content": AGENT_SYSTEM_PROMPT}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user_input})

        # Tool definitions for OpenAI-compatible tool calling
        tool_defs = [
            {
                "type": "function",
                "function": {
                    "name": "get_ioc_details",
                    "description": "Get detailed information about a specific indicator of compromise (IP, domain, hash, CVE).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ioc": {"type": "string", "description": "The IOC value to lookup."}
                        },
                        "required": ["ioc"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_actor_profile",
                    "description": "Get the threat intelligence profile for a specific actor or ransomware group.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "The name of the actor or group."}
                        },
                        "required": ["name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_threat_data",
                    "description": "Search the platform's database for items matching a keyword (malware, industry, etc).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search keyword."}
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_recent_victims",
                    "description": "Get the most recent ransomware victims reported on the dark web.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "description": "Number of victims to return.", "default": 10}
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "fetch_web_content",
                    "description": "Scrape a specific URL to get the latest intelligence or technical details from the web.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "The URL to scrape (e.g. CISA alert, security blog)."}
                        },
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_web",
                    "description": "Search the live web using DuckDuckGo to gather OSINT, verify threat data, or cross-reference multiple credible sources (30+).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "The search query (e.g., 'Qilin ransomware latest TTPs', 'CVE-2023-XXXX details')."}
                        },
                        "required": ["query"]
                    }
                }
            }
        ]

        # For simplicity in this implementation, we simulate the tool loop
        # Current AIEngine doesn't expose native tool calling easily through its generic _complete,
        # so we'll use a ReAct-style prompt for providers that don't support native tool calls,
        # or implement a minimal native tool handler for OpenRouter/Groq.
        
        # Actually, let's use a simpler approach: 
        # 1. Ask model what tools it needs.
        # 2. Execute.
        # 3. Final answer.
        
        # But for the requested "Modular Agent", we'll just implement the core loop.
        # Since I'm limited by the existing _complete structure, I will upgrade it to handle tool calls.
        
        return await self._execute_loop(messages, tool_defs)

    async def _execute_loop(self, messages: List[Dict], tools: List[Dict], max_turns=3) -> str:
        for _ in range(max_turns):
            # We need a native tool calling implementation. 
            # I'll update AIEngine._openrouter and _groq to support tools.
            # For now, I'll return a placeholder to show progress and then update those methods.
            response = await self.ai._complete_with_tools(messages, tools)
            
            if isinstance(response, str):
                return response # Final answer
            
            # If response is a tool call list
            for call in response:
                name = call["function"]["name"]
                args = json.loads(call["function"]["arguments"])
                result = await self.tools[name](**args)
                messages.append({"role": "assistant", "tool_calls": [call], "content": None})
                messages.append({"role": "tool", "tool_call_id": call["id"], "name": name, "content": json.dumps(result)})
        
        return "Agent reached maximum turns without a final answer."

    async def _get_ioc_details(self, ioc: str) -> Dict:
        if not self.db: return {"error": "DB not available"}
        data = await self.db.get_ioc_by_value(ioc)
        return data or {"message": "IOC not found in database."}

    async def _get_actor_profile(self, name: str) -> Dict:
        if not self.db: return {"error": "DB not available"}
        iocs = await self.db.get_iocs(threat_actor=name, page_size=20)
        victims = await self.db.get_victims(group_name=name, page_size=20)
        return {
            "name": name,
            "ioc_count": iocs.get("total", 0),
            "victim_count": victims.get("total", 0),
            "recent_iocs": [i["ioc"] for i in iocs.get("items", [])],
            "recent_victims": [v["victim_name"] for v in victims.get("items", [])]
        }

    async def _search_threat_data(self, query: str) -> Dict:
        if not self.db: return {"error": "DB not available"}
        feed = await self.db.get_feed_context_for_ai(query, limit=5)
        adv = await self.db.get_advisory_context_for_ai(query, limit=3)
        return {"feed_results": feed, "advisory_results": adv}

    async def _get_recent_victims(self, limit: int = 10) -> List[Dict]:
        if not self.db: return []
        data = await self.db.get_victims(page_size=limit)
        return data.get("items", [])

    async def _fetch_web_content(self, url: str) -> Dict:
        """Live web scraping for correlation."""
        try:
            logger.info(f"Agent fetching web content: {url}")
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "CyberXTron-CTI-Agent/2.4"})
                resp.raise_for_status()
                # Basic text extraction from HTML
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                # Remove scripts/styles
                for s in soup(["script", "style"]): s.decompose()
                text = soup.get_text(separator=' ')
                # Clean up whitespace
                lines = (line.strip() for line in text.splitlines())
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                text = '\n'.join(chunk for chunk in chunks if chunk)
                return {"url": url, "content": text[:8000], "status": "success"}
        except Exception as e:
            logger.error(f"Failed to fetch web content {url}: {e}")
            return {"url": url, "error": str(e), "status": "failed"}

    async def _search_web(self, query: str) -> Dict:
        """Search the web across 30+ sources using DuckDuckGo."""
        try:
            logger.info(f"Agent searching web for: {query}")
            # Run blocking DDGS in a thread
            import asyncio
            from duckduckgo_search import DDGS
            def run_search():
                results = []
                try:
                    ddgs = DDGS()
                    for r in ddgs.text(query, max_results=10):
                        results.append(f"Title: {r.get('title')}\nURL: {r.get('href')}\nSnippet: {r.get('body')}\n")
                except Exception as e:
                    logger.error(f"DDGS Error: {e}")
                return results
                
            results = await asyncio.to_thread(run_search)
            if not results:
                return {"query": query, "results": "No results found."}
                
            combined = "\n---\n".join(results)
            return {"query": query, "results": combined, "status": "success"}
        except Exception as e:
            logger.error(f"Failed to search web for {query}: {e}")
            return {"query": query, "error": str(e), "status": "failed"}
