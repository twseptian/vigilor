"""
services/llm_detector.py — Auto-detect Ollama models and validate API keys.
"""
from __future__ import annotations

import httpx


async def detect_ollama_models(base_url: str) -> list[str]:
    """
    Query Ollama /api/tags and return a list of available model names.
    Raises httpx.HTTPError on connection failure.
    """
    url = base_url.rstrip("/") + "/api/tags"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
        models = [m["name"] for m in data.get("models", [])]
        return sorted(models)


def _api_root(base_url: str | None, default: str) -> str:
    """
    Normalise a base URL so we can safely append /v1/models.
    Strips a trailing /v1 (or /v1/) so callers that pass the full
    versioned base (e.g. https://openrouter.ai/api/v1) don't end up
    with a doubled path segment like /api/v1/v1/models.
    """
    root = (base_url or default).rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    return root


async def validate_anthropic_key(api_key: str, base_url: str | None = None) -> list[str]:
    """
    Validate an Anthropic API key by listing available models.
    Returns a list of model IDs on success, raises on failure.
    """
    root = _api_root(base_url, "https://api.anthropic.com")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{root}/v1/models", headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return [m["id"] for m in data.get("data", [])]


async def validate_openai_key(api_key: str, base_url: str | None = None) -> list[str]:
    """
    Validate an OpenAI-compatible API key by listing models.
    Works with OpenAI, OpenRouter, OpenCode, and any /v1-compatible endpoint.
    Falls back gracefully when the provider doesn't implement GET /models.
    """
    root = _api_root(base_url, "https://api.openai.com")
    headers = {"Authorization": f"Bearer {api_key}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{root}/v1/models", headers=headers)
        resp.raise_for_status()

        # Some providers (e.g. OpenCode) return 200 with an empty or non-JSON body
        body = resp.text.strip()
        if not body:
            return []

        try:
            data = resp.json()
        except Exception:
            # Non-JSON 200 — key is valid but models list is unavailable
            return []

        # Standard OpenAI format: { "data": [ { "id": "..." }, ... ] }
        if isinstance(data, dict) and "data" in data:
            return sorted(m["id"] for m in data["data"] if isinstance(m, dict) and "id" in m)

        # Some providers return a flat list: [ { "id": "..." }, ... ]
        if isinstance(data, list):
            return sorted(m["id"] for m in data if isinstance(m, dict) and "id" in m)

        return []
