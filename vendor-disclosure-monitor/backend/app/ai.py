from __future__ import annotations

import os
from typing import Optional, Any

import httpx

AI_PROVIDERS = {"auto", "ollama", "openrouter", "groq"}
_selected_provider: str = os.getenv("AI_PROVIDER", "auto").lower()


def _read_env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(name, default)


def _compose_prompt(title: str, body: str) -> str:
    return (
        "You are a cybersecurity analyst. Rewrite the following disclosure in concise "
        "security advisory style using 3-6 sentences. Keep it factual and avoid hype.\n\n"
        f"Title: {title}\n\n"
        f"Content:\n{body[:6000]}"
    )


def _try_ollama(prompt: str) -> Optional[str]:
    host = _read_env("OLLAMA_BASE_URL", "http://localhost:11434")
    model = _read_env("OLLAMA_MODEL", "llama3.1")
    api_key = _read_env("OLLAMA_API_KEY")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        resp = httpx.post(
            f"{host.rstrip('/')}/api/generate",
            headers=headers,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (data.get("response") or "").strip()
        return text or None
    except Exception:
        # Fallback for OpenAI-compatible Ollama gateways
        try:
            resp = httpx.post(
                f"{host.rstrip('/')}/v1/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                },
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
            text = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )
            return text or None
        except Exception:
            return None


def _ollama_health() -> dict[str, Any]:
    host = _read_env("OLLAMA_BASE_URL", "http://localhost:11434")
    model = _read_env("OLLAMA_MODEL", "llama3.1")
    api_key = _read_env("OLLAMA_API_KEY")
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        resp = httpx.get(f"{host.rstrip('/')}/api/tags", headers=headers, timeout=8)
        resp.raise_for_status()
        tags = resp.json().get("models", [])
        names = [str(m.get("name", "")) for m in tags]
        model_available = any(model in name for name in names)
        return {
            "configured": True,
            "reachable": True,
            "model": model,
            "model_available": model_available,
        }
    except Exception as exc:
        # Fallback probe for OpenAI-compatible gateway where /api/tags may not exist
        try:
            probe = httpx.post(
                f"{host.rstrip('/')}/v1/chat/completions",
                headers={**headers, "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "health check"}],
                    "max_tokens": 4,
                },
                timeout=10,
            )
            probe.raise_for_status()
            return {
                "configured": True,
                "reachable": True,
                "model": model,
                "model_available": True,
                "mode": "openai-compatible",
            }
        except Exception:
            return {
                "configured": True,
                "reachable": False,
                "model": model,
                "model_available": False,
                "error": str(exc),
            }


def _try_openrouter(prompt: str) -> Optional[str]:
    api_key = _read_env("OPENROUTER_API_KEY")
    if not api_key:
        return None
    model = _read_env("OPENROUTER_MODEL", "openai/gpt-4o-mini")
    base_url = _read_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    referer = _read_env("OPENROUTER_HTTP_REFERER")
    title = _read_env("OPENROUTER_X_TITLE")
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title
    try:
        resp = httpx.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            },
            timeout=25,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        return text or None
    except Exception:
        return None


def _try_groq(prompt: str) -> Optional[str]:
    api_key = _read_env("GROQ_API_KEY")
    if not api_key:
        return None
    model = _read_env("GROQ_MODEL", "llama-3.3-70b-versatile")
    base_url = _read_env("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        resp = httpx.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        return text or None
    except Exception:
        return None


def _openrouter_health() -> dict[str, Any]:
    api_key = _read_env("OPENROUTER_API_KEY")
    model = _read_env("OPENROUTER_MODEL", "openai/gpt-4o-mini")
    if not api_key:
        return {
            "configured": False,
            "reachable": False,
            "model": model,
            "error": "OPENROUTER_API_KEY is missing",
        }
    base_url = _read_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/models", headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        models = [str(item.get("id", "")) for item in data.get("data", [])]
        model_available = model in models
        return {
            "configured": True,
            "reachable": True,
            "model": model,
            "model_available": model_available,
        }
    except Exception as exc:
        return {
            "configured": True,
            "reachable": False,
            "model": model,
            "model_available": False,
            "error": str(exc),
        }


def _groq_health() -> dict[str, Any]:
    api_key = _read_env("GROQ_API_KEY")
    model = _read_env("GROQ_MODEL", "llama-3.3-70b-versatile")
    if not api_key:
        return {
            "configured": False,
            "reachable": False,
            "model": model,
            "error": "GROQ_API_KEY is missing",
        }
    base_url = _read_env("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/models", headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        models = [str(item.get("id", "")) for item in data.get("data", [])]
        model_available = model in models
        return {
            "configured": True,
            "reachable": True,
            "model": model,
            "model_available": model_available,
        }
    except Exception as exc:
        return {
            "configured": True,
            "reachable": False,
            "model": model,
            "model_available": False,
            "error": str(exc),
        }


def get_selected_provider() -> str:
    return _selected_provider


def set_selected_provider(provider: str) -> str:
    global _selected_provider
    normalized = (provider or "auto").strip().lower()
    if normalized not in AI_PROVIDERS:
        normalized = "auto"
    _selected_provider = normalized
    return _selected_provider


def generate_advisory_summary(title: str, body: str) -> str:
    """
    Try selected provider or fallback chain.
    Falls back to deterministic local summary if both fail.
    """
    prompt = _compose_prompt(title=title, body=body)
    provider = get_selected_provider()
    if provider == "ollama":
        text = _try_ollama(prompt)
        if text:
            return text
    elif provider == "openrouter":
        text = _try_openrouter(prompt)
        if text:
            return text
    elif provider == "groq":
        text = _try_groq(prompt)
        if text:
            return text
    else:
        for fn in (_try_ollama, _try_openrouter, _try_groq):
            text = fn(prompt)
            if text:
                return text

    # Local fallback summary to keep ingestion reliable.
    preview = " ".join(body.split())[:700]
    if preview:
        return f"{title}. {preview}"
    return title


def get_ai_health() -> dict[str, Any]:
    ollama = _ollama_health()
    openrouter = _openrouter_health()
    groq = _groq_health()

    active_provider = "none"
    if get_selected_provider() != "auto":
        active_provider = get_selected_provider()
    elif ollama.get("reachable") and ollama.get("model_available"):
        active_provider = "ollama"
    elif openrouter.get("reachable") and openrouter.get("configured"):
        active_provider = "openrouter"
    elif groq.get("reachable") and groq.get("configured"):
        active_provider = "groq"

    return {
        "selected_provider": get_selected_provider(),
        "active_provider": active_provider,
        "providers": {
            "ollama": ollama,
            "openrouter": openrouter,
            "groq": groq,
        },
    }

