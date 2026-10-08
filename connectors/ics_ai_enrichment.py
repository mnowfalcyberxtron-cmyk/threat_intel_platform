"""
connectors/ics_ai_enrichment.py

AI-powered background enrichment of ICS advisory fields.

For each ICS advisory where cve_published_date >= '2026-07-01' and ai_enriched = 0:
  1. Fetches raw CVE JSON from GitHub CVEProject/cvelistV5 (patch notes, affected
     products, description, references, etc.)
  2. Sends the combined advisory + CVE data to the AI model with strict formatting rules.
  3. Parses the structured JSON response and writes back:
       - title             (plain-English one-liner)
       - impact            (narrative sentence)
       - affected_version  (Affected: {Product} from vX prior to vY)
       - fixed_version     (Fixed: Update {Product} to vY or later)
       - patch_available_bool  ('True' / 'False')
       - poc_available_bool    ('True' / 'False')
       - xtron_score           (int, calculated by Python logic)
       - ai_enriched = 1
  4. Also reads references[] from the CVE JSON for NVD links, vendor advisories,
     and PoC/exploit references to determine patch/PoC booleans accurately.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("connectors.ics_ai_enrichment")

# ── GitHub CVE fetch helpers ───────────────────────────────────────────────────
_GH_RAW_BASE  = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
_GH_API_BASE  = "https://api.github.com/repos/CVEProject/cvelistV5"
_HTTP_TIMEOUT = 20.0
_CVE_ID_RE    = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)

# Minimum official CVE publish year/month to enrich via AI.
# Advisory release date is intentionally not used for this token-expensive step.
_MIN_RELEASE_YEAR  = 2026
_MIN_RELEASE_MONTH = 7

# Batch size per processing cycle
_BATCH_SIZE    = 4
# Delay between AI calls to avoid rate limits (seconds)
_AI_CALL_DELAY = 8.0
# How often the loop runs (seconds)
_POLL_INTERVAL = 120

# ── Groq/OpenRouter direct call (bypasses the chat AI engine) ─────────────────
_GROQ_URL         = "https://api.groq.com/openai/v1/chat/completions"
_OPENROUTER_URL   = "https://openrouter.ai/api/v1/chat/completions"
_NVIDIA_URL       = "https://integrate.api.nvidia.com/v1/chat/completions"
_GEMINI_URL_BASE  = "https://generativelanguage.googleapis.com/v1beta/models"

_PROVIDER_COOLDOWNS: Dict[Tuple[str, str, str], float] = {}
_RATE_LIMIT_COOLDOWN_SECONDS = 900.0
_PAYMENT_COOLDOWN_SECONDS = 3600.0


def _split_api_keys(value: str) -> List[str]:
    keys: List[str] = []
    seen = set()
    for item in re.split(r"[,;\s]+", value or ""):
        key = item.strip()
        if key and key not in seen:
            keys.append(key)
            seen.add(key)
    return keys


def _provider_key(provider: str, key: str, model: str) -> Tuple[str, str, str]:
    return (provider, key[-12:], model)


def _cooldown_remaining(provider: str, key: str, model: str) -> float:
    until = _PROVIDER_COOLDOWNS.get(_provider_key(provider, key, model), 0.0)
    return max(0.0, until - time.monotonic())


def _cooldown_provider(provider: str, key: str, model: str, seconds: float, reason: str) -> None:
    _PROVIDER_COOLDOWNS[_provider_key(provider, key, model)] = time.monotonic() + seconds
    logger.warning(
        "[ICS-AI] Cooling down %s model=%s for %.0fs after %s.",
        provider,
        model,
        seconds,
        reason,
    )


# ── XTRON Score logic ──────────────────────────────────────────────────────────
def _calc_xtron_score(severity: str, poc_bool: bool) -> int:
    """
    XTRON SCORE formula:
      POC bonus: +10 if PoC/active exploitation confirmed
      Severity:  Critical=65, High=60, Medium=50, Low=35, else 0
    """
    sev = str(severity or "").strip().lower()
    sev_score = 65 if sev == "critical" else (
                60 if sev == "high" else (
                50 if sev == "medium" else (
                35 if sev == "low" else 0)))
    poc_score = 10 if poc_bool else 0
    return sev_score + poc_score


# ── CVE GitHub fetcher ─────────────────────────────────────────────────────────

def _cve_to_github_path(cve_id: str) -> Optional[str]:
    """Convert CVE-YYYY-NNNNN to the cvelistV5 file path."""
    m = _CVE_ID_RE.match(cve_id.strip())
    if not m:
        return None
    year = m.group(1)
    num  = m.group(2)
    folder = (num[:-3] + "xxx") if len(num) > 3 else "0xxx"
    return f"cves/{year}/{folder}/{cve_id.upper()}.json"


async def _fetch_cve_json(client: httpx.AsyncClient, cve_id: str, github_token: Optional[str] = None) -> Optional[dict]:
    """Fetch raw CVE JSON from GitHub CVEProject/cvelistV5."""
    path = _cve_to_github_path(cve_id)
    if not path:
        return None
    url = f"{_GH_RAW_BASE}/{path}"
    headers = {"User-Agent": "ThreatIntel-TIP/2.5"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    try:
        r = await client.get(url, headers=headers, timeout=_HTTP_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        logger.debug("[ICS-AI] CVE JSON fetch %d for %s", r.status_code, cve_id)
        return None
    except Exception as e:
        logger.debug("[ICS-AI] CVE JSON fetch error for %s: %s", cve_id, e)
        return None


# ── Extract intelligence from the raw CVE JSON ────────────────────────────────

def _extract_from_cve_json(data: dict) -> Dict[str, Any]:
    """
    Pull the most useful fields out of the raw CVE JSON for the AI prompt.
    Returns a dict with: description, affected_products, references, state, patch_refs
    """
    result = {
        "description": "",
        "affected_products": [],
        "references": [],
        "patch_refs": [],
        "exploit_refs": [],
        "state": "",
        "date_published": "",
        "date_updated": "",
        "cvss_scores": [],
    }

    meta = data.get("cveMetadata") or {}
    result["state"] = str(meta.get("state") or "")
    result["date_published"] = str(meta.get("datePublished") or "")
    result["date_updated"] = str(meta.get("dateUpdated") or "")

    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}

    # Description
    descs = cna.get("descriptions") or []
    for d in descs:
        if d.get("lang", "").lower().startswith("en"):
            result["description"] = str(d.get("value") or "")
            break
    if not result["description"] and descs:
        result["description"] = str(descs[0].get("value") or "")

    # Affected products
    for affected in (cna.get("affected") or []):
        vendor  = str(affected.get("vendor") or "")
        product = str(affected.get("product") or "")
        versions = []
        for v in (affected.get("versions") or []):
            status = str(v.get("status") or "")
            ver    = str(v.get("version") or "")
            lt     = str(v.get("lessThan") or v.get("lessThanOrEqual") or "")
            if ver or lt:
                versions.append({"version": ver, "lessThan": lt, "status": status})
        result["affected_products"].append({
            "vendor": vendor,
            "product": product,
            "versions": versions,
        })

    # References — classify by tags
    for ref in (cna.get("references") or []):
        url  = str(ref.get("url") or "")
        tags = [t.lower() for t in (ref.get("tags") or [])]
        result["references"].append({"url": url, "tags": tags})
        if any(t in ("patch", "vendor-advisory", "fix") for t in tags):
            result["patch_refs"].append(url)
        if any(t in ("exploit", "third-party-advisory", "poc") for t in tags):
            result["exploit_refs"].append(url)

    # CVSS scores
    metrics = cna.get("metrics") or []
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if key in m:
                score = m[key].get("baseScore")
                vec   = m[key].get("vectorString", "")
                if score:
                    result["cvss_scores"].append({"score": score, "vector": vec})

    return result


def _infer_patch_bool_from_cve(cve_info: Dict[str, Any], db_patch: str) -> bool:
    """
    Determine patch availability from CVE JSON data + existing DB value.
    True only if there are confirmed vendor-advisory/patch-tagged references.
    """
    # Already marked True in DB from previous enrichment
    if str(db_patch).strip().lower() in ("true", "yes", "1"):
        return True
    # CVE JSON has patch-tagged references
    if cve_info.get("patch_refs"):
        return True
    # CVE state "PUBLISHED" with vendor advisory tags in any ref
    refs = cve_info.get("references") or []
    for ref in refs:
        tags = ref.get("tags") or []
        if any(t in ("patch", "vendor-advisory") for t in tags):
            return True
    return False


def _infer_poc_bool_from_cve(cve_info: Dict[str, Any], kev_flag: str) -> bool:
    """
    Determine PoC/exploitation confirmation.
    True only if:
    - kev_flag is set (CISA KEV confirmed), or
    - CVE JSON references have exploit/poc tags.
    """
    if str(kev_flag or "").strip().lower() in ("true", "yes", "1", "kev"):
        return True
    if cve_info.get("exploit_refs"):
        return True
    refs = cve_info.get("references") or []
    for ref in refs:
        tags = ref.get("tags") or []
        if any(t in ("exploit", "poc") for t in tags):
            return True
    return False


# ── AI call (direct, no tool schema needed) ────────────────────────────────────

_ENRICH_SYSTEM_PROMPT = """\
You are an Operational Technology (OT) and ICS/SCADA cybersecurity expert writing advisories for industrial control systems, SCADA, PLCs, HMIs, and OT-embedded devices.
You will receive raw advisory data and CVE JSON information.
You MUST respond with ONLY a valid JSON object — no markdown, no explanation, no preamble.

JSON schema to return:
{
  "vendor": "Primary OT/hardware/software vendor responsible for the vulnerability (e.g. Fortinet, Siemens, Schneider Electric)",
  "product": "Primary affected OT software/hardware product name (e.g. FortiOS, RUGGEDCOM APE1808, Modicon)",
  "title": "One-line plain-English summary of the actual OT vulnerability (not just the product name). Max 120 chars.",
  "impact": "A successful exploit may allow [attacker type] to [action], resulting in [consequence].",
  "affected_text": "{Product} from v{X} prior to v{Y}",
  "fixed_text": "Update {Product} to v{Y} or later",
  "patch_note": "Brief reason if no fix available, or empty string if fix exists",
  "poc_note": "No known public exploitation reported to CISA"
}

Rules:
- OT Focus: Keep focus strictly on Operational Technology (OT), SCADA, and Industrial Control Systems context.
- vendor: MUST use the official vendor name from the GitHub CVE JSON (e.g. 'Milestone Systems' or 'Fortinet' instead of advisory publisher 'Siemens').
- product: MUST use the official product name from the GitHub CVE JSON (e.g. 'XProtect Management Server' or 'FortiOS').
- title: describe the vulnerability class and what it affects, not just the product name.
- impact: always start with 'A successful exploit may allow'. Fill [attacker type] from context (e.g. 'an unauthenticated remote attacker', 'a local attacker with network access').
- affected_text: DO NOT prefix with 'Affected:'. If no lower bound published, write '{Product} prior to v{Y}'. If no fixed version exists, write '{Product} v{X} and all prior versions (no fixed version currently available)'.
- fixed_text: DO NOT prefix with 'Fixed:'. If no fix exists write 'No fixed version available — {reason}'.
- poc_note: default is exactly 'No known public exploitation reported to CISA'. Only change if there is confirmed exploitation.
- Keep all values concise and professional.
"""


async def _call_ai_for_enrichment(
    client: httpx.AsyncClient,
    row: Dict,
    cve_info: Dict,
    groq_key: str,
    groq_model: str,
    openrouter_key: str,
    openrouter_model: str,
    ollama_base_url: str,
    ollama_model: str,
    ollama_key: str,
    nvidia_key: str,
    nvidia_model: str,
    gemini_key: str,
    gemini_model: str,
) -> Optional[Dict]:
    """Call AI with advisory + CVE context, parse JSON response."""

    # Build a compact context string
    affected_str = ""
    for ap in (cve_info.get("affected_products") or [])[:3]:
        vlist = ", ".join(
            f"v{v['version']} < v{v['lessThan']}" if v.get("lessThan") else f"v{v['version']}"
            for v in ap.get("versions", [])[:3]
        )
        affected_str += f"  - {ap['vendor']} {ap['product']}: {vlist}\n"

    ref_str = "\n".join(
        f"  [{','.join(r.get('tags',[]))}] {r['url']}"
        for r in (cve_info.get("references") or [])[:10]
    )

    user_content = f"""
ICS Advisory Data:
  Advisory: {row.get('ics_number', '')}
  CVE-ID: {row.get('cve_id', '')}
  Vendor: {row.get('vendor', '')}
  Product: {row.get('product', '')}
  Severity: {row.get('severity', '')}
  CVSS Score: {row.get('cvss_score', '')}
  Sector: {row.get('sector', '')}
  CWE: {row.get('cwe', '')}
  Existing Impact: {row.get('impact', '')}
  Existing Affected Version: {row.get('affected_version', '')}
  Existing Fixed Version: {row.get('fixed_version', '')}
  KEV Flag: {row.get('kev_flag', '')}
  Patch Availability: {row.get('patch_availability', '')}
  PoC Availability: {row.get('poc_availability', '')}

CVE JSON Data:
  Description: {cve_info.get('description', '')[:800]}
  State: {cve_info.get('state', '')}
  Published: {cve_info.get('date_published', '')}
  
Affected Products (from CVE JSON):
{affected_str or '  (not specified in CVE JSON)'}

References (from CVE JSON):
{ref_str or '  (none)'}
"""

    messages = [
        {"role": "system", "content": _ENRICH_SYSTEM_PROMPT},
        {"role": "user", "content": user_content.strip()},
    ]

    # Try all configured providers in order; rows stay queued if every provider fails.
    providers = []
    for key in _split_api_keys(groq_key):
        providers.append(("groq", key, groq_model))
    if openrouter_key:
        providers.append(("openrouter", openrouter_key, openrouter_model))
    if ollama_base_url and ollama_model:
        providers.append(("ollama", ollama_key, ollama_model))
    if nvidia_key:
        providers.append(("nvidia", nvidia_key, nvidia_model))
    if gemini_key:
        providers.append(("gemini", gemini_key, gemini_model))

    for (provider, key, model) in providers:
        try:
            cooldown_left = _cooldown_remaining(provider, key, model)
            if cooldown_left > 0:
                logger.info(
                    "[ICS-AI] Skipping %s model=%s; cooldown %.0fs remaining.",
                    provider,
                    model,
                    cooldown_left,
                )
                continue

            # Build provider-specific payload
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 1600,
                "response_format": {"type": "json_object"},
            }
            if provider == "groq":
                headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
                url = _GROQ_URL
            elif provider == "ollama":
                url = f"{ollama_base_url.rstrip('/')}/api/chat"
                headers = {"Content-Type": "application/json"}
                if key:
                    headers["Authorization"] = f"Bearer {key}"
                payload = {
                    "model": model,
                    "messages": messages,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 1600,
                    },
                }
            elif provider in {"openrouter", "nvidia"}:
                url = _NVIDIA_URL if provider == "nvidia" else _OPENROUTER_URL
                headers = {
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
                if provider == "openrouter":
                    headers["HTTP-Referer"] = "https://threatintel.local"
                    headers["X-Title"] = "ThreatIntel TIP"
                if provider == "nvidia":
                    payload.pop("response_format", None)
            else:
                url = f"{_GEMINI_URL_BASE}/{model}:generateContent"
                headers = {"Content-Type": "application/json", "X-goog-api-key": key}
                payload = {
                    "systemInstruction": {
                        "parts": [{"text": _ENRICH_SYSTEM_PROMPT}]
                    },
                    "contents": [
                        {
                            "role": "user",
                            "parts": [{"text": user_content.strip()}],
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 1600,
                        "responseMimeType": "application/json",
                    },
                }

            resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
            if resp.status_code in (400, 422) and "response_format" in payload:
                retry_payload = dict(payload)
                retry_payload.pop("response_format", None)
                resp = await client.post(url, headers=headers, json=retry_payload, timeout=30.0)
            if resp.status_code != 200:
                if resp.status_code == 429:
                    _cooldown_provider(provider, key, model, _RATE_LIMIT_COOLDOWN_SECONDS, "HTTP 429")
                elif resp.status_code == 402:
                    _cooldown_provider(provider, key, model, _PAYMENT_COOLDOWN_SECONDS, "HTTP 402")
                logger.warning("[ICS-AI] %s returned %d: %s", provider, resp.status_code, resp.text[:200])
                continue

            data = resp.json()
            if provider == "gemini":
                content = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
                )
            elif provider == "ollama":
                content = data.get("message", {}).get("content", "")
            else:
                content = data["choices"][0]["message"]["content"]
            # Clean possible markdown codeblocks if provider returns ```json ... ```
            clean_content = content.strip()
            if clean_content.startswith("```"):
                clean_content = re.sub(r"^```(?:json)?\s*", "", clean_content, flags=re.IGNORECASE)
                clean_content = re.sub(r"\s*```$", "", clean_content)

            try:
                parsed = json.loads(clean_content)
                return parsed
            except json.JSONDecodeError:
                # Try regex extraction for single JSON object
                m = re.search(r"\{.*\}", clean_content, re.DOTALL)
                if m:
                    try:
                        return json.loads(m.group(0))
                    except Exception:
                        pass
                logger.warning("[ICS-AI] Could not parse JSON from %s response: %s", provider, content[:200])

        except Exception as e:
            logger.warning("[ICS-AI] %s error for %s: %s", provider, row.get("cve_id"), e)

    return None


# ── DB helpers ─────────────────────────────────────────────────────────────────

async def _fetch_unenriched(db, batch_size: int) -> List[Dict]:
    """
    Return ICS rows needing AI enrichment.
    Criteria: ai_enriched=0 AND official CVE publish date is July 2026 or later.
    Uses cve_pub_year/cve_pub_month from CVEProject/cvelistV5, not CISA advisory
    release dates, so old CVEs inside newer advisories do not spend AI tokens.
    """
    async with db._conn.execute(
        """
        SELECT id, ics_number, cve_id, title, vendor, product, severity,
               cvss_score, sector, cwe, impact, affected_version, fixed_version,
               patch_availability, poc_availability, kev_flag,
               cve_published_date, cve_updated_date, cve_pub_year, cve_pub_month,
               release_year, release_month
        FROM ics_advisories
        WHERE (ai_enriched IS NULL OR ai_enriched = 0)
          AND (
            (release_year > ? OR (release_year = ? AND release_month >= ?))
          )
          AND cve_id IS NOT NULL
          AND TRIM(UPPER(cve_id)) NOT IN ('N/A', 'NONE', '')
        ORDER BY release_year ASC, release_month ASC, cve_published_date ASC, id ASC
        LIMIT ?
        """,
        (_MIN_RELEASE_YEAR, _MIN_RELEASE_YEAR, _MIN_RELEASE_MONTH, batch_size),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


def _json_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _merge_ai_blob(blob: Any, ai: Dict, aff_text: str, fix_text: str, patch_bool: bool, poc_bool: bool, score: int) -> str:
    data = _json_dict(blob)
    ai_vendor = (ai.get("vendor") or "").strip()
    ai_product = (ai.get("product") or "").strip()
    updates = {
        "ai_enriched": 1,
        "ai_enrichment_source": "ics_ai_enrichment",
        "patch_available_bool": "True" if patch_bool else "False",
        "poc_available_bool": "True" if poc_bool else "False",
        "xtron_score": score,
        "affected_vendor": ai_vendor,
        "affected_application": ai_product,
        "vendor": ai_vendor,
        "product": ai_product,
        "title": ai.get("title", ""),
        "impact": ai.get("impact", ""),
        "affected_version": aff_text,
        "fixed_version": fix_text,
    }
    for key, value in updates.items():
        if value not in (None, ""):
            data[key] = value
    return json.dumps(data)


async def _write_enrichment(db, row_id: int, ai: Dict, patch_bool: bool, poc_bool: bool, score: int) -> None:
    """Write the AI-enriched fields back to the DB."""
    # Strip any "Affected:" or "Fixed:" label prefix the AI adds despite prompt instructions
    _pfx = re.compile(r'^(?:affected|fixed)\s*:\s*', re.IGNORECASE)
    aff_text = _pfx.sub("", ai.get("affected_text", "")).strip()
    fix_text  = _pfx.sub("", ai.get("fixed_text",   "")).strip()
    ai_vendor = (ai.get("vendor") or "").strip()
    ai_product = (ai.get("product") or "").strip()
    async with db._conn.execute(
        "SELECT raw_data, normalized_data FROM ics_advisories WHERE id=?",
        (row_id,),
    ) as cur:
        row = await cur.fetchone()
    raw_data = _merge_ai_blob(row["raw_data"] if row else "{}", ai, aff_text, fix_text, patch_bool, poc_bool, score)
    normalized_data = _merge_ai_blob(row["normalized_data"] if row else "{}", ai, aff_text, fix_text, patch_bool, poc_bool, score)

    await db._conn.execute(
        """
        UPDATE ics_advisories SET
            vendor              = CASE WHEN ? != '' THEN ? ELSE vendor END,
            product             = CASE WHEN ? != '' THEN ? ELSE product END,
            title               = CASE WHEN ? != '' THEN ? ELSE title END,
            impact              = CASE WHEN ? != '' THEN ? ELSE impact END,
            affected_version    = CASE WHEN ? != '' THEN ? ELSE affected_version END,
            fixed_version       = CASE WHEN ? != '' THEN ? ELSE fixed_version END,
            patch_available_bool = ?,
            poc_available_bool   = ?,
            xtron_score          = ?,
            ai_enriched          = 1,
            raw_data             = ?,
            normalized_data      = ?,
            updated_at           = ?
        WHERE id = ?
        """,
        (
            ai_vendor, ai_vendor,
            ai_product, ai_product,
            ai.get("title", ""), ai.get("title", ""),
            ai.get("impact", ""), ai.get("impact", ""),
            aff_text, aff_text,
            fix_text, fix_text,
            "True" if patch_bool else "False",
            "True" if poc_bool else "False",
            score,
            raw_data,
            normalized_data,
            datetime.now(timezone.utc).isoformat(),
            row_id,
        ),
    )


# ── Main enrichment loop ───────────────────────────────────────────────────────

async def run_ics_ai_enrichment_loop(
    db,
    *,
    startup_delay: float = 60.0,
    poll_interval: float = _POLL_INTERVAL,
):
    """
    Background loop: continuously enriches ICS advisories (CVE pub >= 2026-07-01)
    using AI and GitHub CVE JSON data.
    """
    try:
        from config import settings as cfg
        groq_key      = getattr(cfg, "GROQ_API_KEY", "") or ""
        groq_keys     = getattr(cfg, "GROQ_API_KEYS", "") or ""
        groq_model    = getattr(cfg, "GROQ_MODEL", "llama3-70b-8192") or "llama3-70b-8192"
        openrouter_key   = getattr(cfg, "OPENROUTER_API_KEY", "") or ""
        openrouter_model = getattr(cfg, "OPENROUTER_MODEL", "google/gemma-4-31b-it") or "google/gemma-4-31b-it"
        ollama_base_url = getattr(cfg, "OLLAMA_BASE_URL", "http://localhost:11434") or "http://localhost:11434"
        ollama_model = getattr(cfg, "OLLAMA_MODEL", "llama3") or "llama3"
        ollama_api_key = getattr(cfg, "OLLAMA_API_KEY", "") or ""
        nvidia_key    = getattr(cfg, "NVIDIA_API_KEY", "") or ""
        nvidia_model  = getattr(cfg, "NVIDIA_MODEL", "openai/gpt-oss-20b") or "openai/gpt-oss-20b"
        gemini_key    = getattr(cfg, "GEMINI_API_KEY", "") or ""
        gemini_model  = getattr(cfg, "GEMINI_MODEL", "gemini-flash-latest") or "gemini-flash-latest"
        github_token  = getattr(cfg, "GITHUB_TOKEN", "") or ""
    except Exception:
        groq_key = groq_keys = groq_model = openrouter_key = openrouter_model = ollama_base_url = ollama_model = ollama_api_key = nvidia_key = nvidia_model = gemini_key = gemini_model = github_token = ""

    groq_key = " ".join(key for key in (groq_key, groq_keys) if key)

    if not groq_key and not openrouter_key and not ollama_base_url and not nvidia_key and not gemini_key:
        logger.warning("[ICS-AI] No AI provider configured — enrichment loop not started.")
        return

    logger.info(
        "[ICS-AI] Enrichment loop starting in %.0fs (min advisory date: %d-%02d, batch: %d).",
        startup_delay, _MIN_RELEASE_YEAR, _MIN_RELEASE_MONTH, _BATCH_SIZE,
    )
    await asyncio.sleep(startup_delay)

    # Add new DB columns if they don't already exist (safe migration)
    for col_sql in [
        "ALTER TABLE ics_advisories ADD COLUMN ai_enriched INTEGER DEFAULT 0",
        "ALTER TABLE ics_advisories ADD COLUMN patch_available_bool TEXT DEFAULT ''",
        "ALTER TABLE ics_advisories ADD COLUMN poc_available_bool TEXT DEFAULT ''",
        "ALTER TABLE ics_advisories ADD COLUMN xtron_score INTEGER DEFAULT NULL",
    ]:
        try:
            await db._conn.execute(col_sql)
            await db._conn.commit()
        except Exception:
            pass  # Column already exists

    logger.info("[ICS-AI] Enrichment loop running.")

    async with httpx.AsyncClient() as client:
        while True:
            try:
                rows = await _fetch_unenriched(db, _BATCH_SIZE)
                if not rows:
                    logger.debug("[ICS-AI] No unenriched rows found. Sleeping %ds.", poll_interval)
                    await asyncio.sleep(poll_interval)
                    continue

                logger.info("[ICS-AI] Processing batch of %d unenriched advisories.", len(rows))

                done = skipped = 0
                for row in rows:
                    cve_id = str(row.get("cve_id") or "").strip().upper()
                    row_id = row["id"]

                    # 1. Fetch CVE JSON from GitHub
                    cve_info = {}
                    raw_cve  = await _fetch_cve_json(client, cve_id, github_token)
                    if raw_cve:
                        cve_info = _extract_from_cve_json(raw_cve)

                    # 2. Infer Patch/PoC from CVE JSON + existing DB data
                    patch_bool = _infer_patch_bool_from_cve(cve_info, row.get("patch_availability", ""))
                    poc_bool   = _infer_poc_bool_from_cve(cve_info, row.get("kev_flag", ""))

                    # 3. Calculate XTRON score using Python logic
                    score = _calc_xtron_score(row.get("severity", ""), poc_bool)

                    # 4. Call AI for narrative rewrite
                    ai_result = await _call_ai_for_enrichment(
                        client, row, cve_info,
                        groq_key, groq_model,
                        openrouter_key, openrouter_model,
                        ollama_base_url, ollama_model, ollama_api_key,
                        nvidia_key, nvidia_model,
                        gemini_key, gemini_model,
                    )

                    if ai_result:
                        await _write_enrichment(db, row_id, ai_result, patch_bool, poc_bool, score)
                        done += 1
                        logger.debug(
                            "[ICS-AI] Enriched %s | XTRON=%d | Patch=%s | PoC=%s",
                            cve_id, score, patch_bool, poc_bool,
                        )
                    else:
                        # Save deterministic fields, but do not mark the row AI-enriched.
                        # Only successful narrative enrichment gets ai_enriched=1.
                        await db._conn.execute(
                            """UPDATE ics_advisories SET
                               patch_available_bool = ?,
                               poc_available_bool   = ?,
                               xtron_score          = ?,
                               ai_enriched          = 0,
                               updated_at           = ?
                               WHERE id = ?""",
                            (
                                "True" if patch_bool else "False",
                                "True" if poc_bool else "False",
                                score,
                                datetime.now(timezone.utc).isoformat(),
                                row_id,
                            ),
                        )
                        skipped += 1

                    await db._conn.commit()
                    await asyncio.sleep(_AI_CALL_DELAY)

                logger.info(
                    "[ICS-AI] Batch complete: %d enriched, %d scores-only.",
                    done, skipped,
                )

            except Exception as exc:
                logger.error("[ICS-AI] Enrichment loop error: %s", exc, exc_info=True)

            await asyncio.sleep(poll_interval)
