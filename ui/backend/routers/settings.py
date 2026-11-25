"""routers/settings.py — API keys, LLM config, Ollama model detection."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user, require_min_role
from backend.models.settings import GlobalSettings
from backend.models.user import User
from backend.services.crypto import encrypt_value, decrypt_value
from backend.services.llm_detector import (
    detect_ollama_models,
    validate_anthropic_key,
    validate_openai_key,
    validate_openrouter_key,
)

router = APIRouter(prefix="/settings", tags=["settings"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class SettingsOut(BaseModel):
    anthropic_key_set: bool
    anthropic_base_url: str | None
    anthropic_max_tokens: int
    anthropic_temperature: float | None
    anthropic_top_p: float | None
    openai_key_set: bool
    openai_base_url: str | None
    openai_max_tokens: int
    openai_default_model: str | None
    openai_temperature: float | None
    openai_top_p: float | None
    openai_frequency_penalty: float | None
    openai_presence_penalty: float | None
    openrouter_key_set: bool
    openrouter_auth_method: str
    openrouter_base_url: str | None
    openrouter_max_tokens: int
    openrouter_default_model: str | None
    openrouter_temperature: float | None
    openrouter_top_p: float | None
    mistral_key_set: bool
    mistral_base_url: str | None
    mistral_max_tokens: int
    mistral_default_model: str | None
    mistral_temperature: float | None
    mistral_top_p: float | None
    groq_key_set: bool
    groq_base_url: str | None
    groq_max_tokens: int
    groq_default_model: str | None
    groq_temperature: float | None
    groq_top_p: float | None
    xai_key_set: bool
    xai_base_url: str | None
    xai_max_tokens: int
    xai_default_model: str | None
    xai_temperature: float | None
    xai_top_p: float | None
    deepseek_key_set: bool
    deepseek_base_url: str | None
    deepseek_max_tokens: int
    deepseek_default_model: str | None
    deepseek_temperature: float | None
    deepseek_top_p: float | None
    kimi_key_set: bool
    kimi_base_url: str | None
    kimi_max_tokens: int
    kimi_default_model: str | None
    kimi_temperature: float | None
    kimi_top_p: float | None
    zai_key_set: bool
    zai_base_url: str | None
    zai_max_tokens: int
    zai_default_model: str | None
    zai_temperature: float | None
    zai_top_p: float | None
    ollama_mode: str
    ollama_key_set: bool
    ollama_base_url: str | None
    ollama_default_model: str | None
    ollama_temperature: float | None
    ollama_num_ctx: int | None
    ollama_max_tokens: int | None
    ollama_top_p: float | None
    ollama_top_k: int | None
    ollama_repeat_penalty: float | None
    scan_max_rps: float | None
    max_concurrent_scans: int
    smtp_host: str | None
    smtp_port: int | None
    smtp_user: str | None
    smtp_from: str | None
    slack_configured: bool


class SettingsUpdate(BaseModel):
    anthropic_api_key: str | None = None
    anthropic_base_url: str | None = None
    anthropic_max_tokens: int | None = None
    anthropic_temperature: float | None = None
    anthropic_top_p: float | None = None
    openai_api_key: str | None = None
    openai_base_url: str | None = None
    openai_max_tokens: int | None = None
    openai_default_model: str | None = None
    openai_temperature: float | None = None
    openai_top_p: float | None = None
    openai_frequency_penalty: float | None = None
    openai_presence_penalty: float | None = None
    openrouter_api_key: str | None = None
    openrouter_base_url: str | None = None
    openrouter_max_tokens: int | None = None
    openrouter_default_model: str | None = None
    openrouter_temperature: float | None = None
    openrouter_top_p: float | None = None
    mistral_api_key: str | None = None
    mistral_base_url: str | None = None
    mistral_max_tokens: int | None = None
    mistral_default_model: str | None = None
    mistral_temperature: float | None = None
    mistral_top_p: float | None = None
    groq_api_key: str | None = None
    groq_base_url: str | None = None
    groq_max_tokens: int | None = None
    groq_default_model: str | None = None
    groq_temperature: float | None = None
    groq_top_p: float | None = None
    xai_api_key: str | None = None
    xai_base_url: str | None = None
    xai_max_tokens: int | None = None
    xai_default_model: str | None = None
    xai_temperature: float | None = None
    xai_top_p: float | None = None
    deepseek_api_key: str | None = None
    deepseek_base_url: str | None = None
    deepseek_max_tokens: int | None = None
    deepseek_default_model: str | None = None
    deepseek_temperature: float | None = None
    deepseek_top_p: float | None = None
    kimi_api_key: str | None = None
    kimi_base_url: str | None = None
    kimi_max_tokens: int | None = None
    kimi_default_model: str | None = None
    kimi_temperature: float | None = None
    kimi_top_p: float | None = None
    zai_api_key: str | None = None
    zai_base_url: str | None = None
    zai_max_tokens: int | None = None
    zai_default_model: str | None = None
    zai_temperature: float | None = None
    zai_top_p: float | None = None
    ollama_mode: str | None = None
    ollama_api_key: str | None = None
    ollama_base_url: str | None = None
    ollama_default_model: str | None = None
    ollama_temperature: float | None = None
    ollama_num_ctx: int | None = None
    ollama_max_tokens: int | None = None
    ollama_top_p: float | None = None
    ollama_top_k: int | None = None
    ollama_repeat_penalty: float | None = None
    scan_max_rps: float | None = None
    max_concurrent_scans: int | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    slack_webhook: str | None = None


class TestLlmRequest(BaseModel):
    provider: str
    api_key: str
    base_url: str | None = None
    ollama_url: str | None = None


class TestLlmResponse(BaseModel):
    valid: bool
    models: list[str] = []
    error: str | None = None


class DetectOllamaRequest(BaseModel):
    base_url: str


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_or_create_settings(db: AsyncSession) -> GlobalSettings:
    gs = await db.get(GlobalSettings, 1)
    if gs is None:
        gs = GlobalSettings(id=1)
        db.add(gs)
        await db.flush()
    return gs


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=SettingsOut)
async def get_settings(
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> SettingsOut:
    gs = await _get_or_create_settings(db)
    return _to_settings_out(gs)


def _to_settings_out(gs: GlobalSettings) -> SettingsOut:
    return SettingsOut(
        anthropic_key_set=bool(gs.anthropic_api_key_enc),
        anthropic_base_url=gs.anthropic_base_url or "https://api.anthropic.com",
        anthropic_max_tokens=gs.anthropic_max_tokens or 4096,
        anthropic_temperature=gs.anthropic_temperature if gs.anthropic_temperature is not None else 0.7,
        anthropic_top_p=gs.anthropic_top_p,
        openai_key_set=bool(gs.openai_api_key_enc),
        openai_base_url=gs.openai_base_url or "https://api.openai.com/v1",
        openai_max_tokens=gs.openai_max_tokens or 4096,
        openai_default_model=gs.openai_default_model,
        openai_temperature=gs.openai_temperature if gs.openai_temperature is not None else 0.7,
        openai_top_p=gs.openai_top_p,
        openai_frequency_penalty=gs.openai_frequency_penalty if gs.openai_frequency_penalty is not None else 0.0,
        openai_presence_penalty=gs.openai_presence_penalty if gs.openai_presence_penalty is not None else 0.0,
        openrouter_key_set=bool(gs.openrouter_api_key_enc),
        openrouter_auth_method=gs.openrouter_auth_method or "manual",
        openrouter_base_url=gs.openrouter_base_url or "https://openrouter.ai/api/v1",
        openrouter_max_tokens=gs.openrouter_max_tokens or 4096,
        openrouter_default_model=gs.openrouter_default_model,
        openrouter_temperature=gs.openrouter_temperature if gs.openrouter_temperature is not None else 0.7,
        openrouter_top_p=gs.openrouter_top_p,
        mistral_key_set=bool(gs.mistral_api_key_enc),
        mistral_base_url=gs.mistral_base_url or "https://api.mistral.ai/v1",
        mistral_max_tokens=gs.mistral_max_tokens or 4096,
        mistral_default_model=gs.mistral_default_model,
        mistral_temperature=gs.mistral_temperature if gs.mistral_temperature is not None else 0.7,
        mistral_top_p=gs.mistral_top_p,
        groq_key_set=bool(gs.groq_api_key_enc),
        groq_base_url=gs.groq_base_url or "https://api.groq.com/openai/v1",
        groq_max_tokens=gs.groq_max_tokens or 4096,
        groq_default_model=gs.groq_default_model,
        groq_temperature=gs.groq_temperature if gs.groq_temperature is not None else 0.7,
        groq_top_p=gs.groq_top_p,
        xai_key_set=bool(gs.xai_api_key_enc),
        xai_base_url=gs.xai_base_url or "https://api.x.ai/v1",
        xai_max_tokens=gs.xai_max_tokens or 4096,
        xai_default_model=gs.xai_default_model,
        xai_temperature=gs.xai_temperature if gs.xai_temperature is not None else 0.7,
        xai_top_p=gs.xai_top_p,
        deepseek_key_set=bool(gs.deepseek_api_key_enc),
        deepseek_base_url=gs.deepseek_base_url or "https://api.deepseek.com",
        deepseek_max_tokens=gs.deepseek_max_tokens or 4096,
        deepseek_default_model=gs.deepseek_default_model,
        deepseek_temperature=gs.deepseek_temperature if gs.deepseek_temperature is not None else 0.7,
        deepseek_top_p=gs.deepseek_top_p,
        kimi_key_set=bool(gs.kimi_api_key_enc),
        kimi_base_url=gs.kimi_base_url or "https://api.moonshot.ai/v1",
        kimi_max_tokens=gs.kimi_max_tokens or 4096,
        kimi_default_model=gs.kimi_default_model,
        kimi_temperature=gs.kimi_temperature if gs.kimi_temperature is not None else 0.7,
        kimi_top_p=gs.kimi_top_p,
        zai_key_set=bool(gs.zai_api_key_enc),
        zai_base_url=gs.zai_base_url or "https://api.z.ai/api/paas/v4",
        zai_max_tokens=gs.zai_max_tokens or 4096,
        zai_default_model=gs.zai_default_model,
        zai_temperature=gs.zai_temperature if gs.zai_temperature is not None else 0.7,
        zai_top_p=gs.zai_top_p,
        ollama_mode=gs.ollama_mode or "local",
        ollama_key_set=bool(gs.ollama_api_key_enc),
        ollama_base_url=gs.ollama_base_url,
        ollama_default_model=gs.ollama_default_model,
        ollama_temperature=gs.ollama_temperature,
        ollama_num_ctx=gs.ollama_num_ctx,
        ollama_max_tokens=gs.ollama_max_tokens,
        ollama_top_p=gs.ollama_top_p,
        ollama_top_k=gs.ollama_top_k,
        ollama_repeat_penalty=gs.ollama_repeat_penalty,
        scan_max_rps=gs.scan_max_rps if gs.scan_max_rps is not None else 0.0,
        max_concurrent_scans=gs.max_concurrent_scans,
        smtp_host=gs.smtp_host,
        smtp_port=gs.smtp_port,
        smtp_user=gs.smtp_user,
        smtp_from=gs.smtp_from,
        slack_configured=bool(gs.slack_webhook_enc),
    )


@router.patch("", response_model=SettingsOut)
async def update_settings(
    body: SettingsUpdate,
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> SettingsOut:
    gs = await _get_or_create_settings(db)

    if body.anthropic_api_key is not None:
        gs.anthropic_api_key_enc = encrypt_value(body.anthropic_api_key) if body.anthropic_api_key else None
    if body.anthropic_base_url is not None:
        gs.anthropic_base_url = body.anthropic_base_url or "https://api.anthropic.com"
    if body.anthropic_max_tokens is not None:
        gs.anthropic_max_tokens = max(256, min(body.anthropic_max_tokens, 32768))
    if body.anthropic_temperature is not None:
        gs.anthropic_temperature = max(0.0, min(body.anthropic_temperature, 1.0))
    if "anthropic_top_p" in body.model_fields_set:
        gs.anthropic_top_p = body.anthropic_top_p
    if body.openai_api_key is not None:
        gs.openai_api_key_enc = encrypt_value(body.openai_api_key) if body.openai_api_key else None
    if body.openai_base_url is not None:
        gs.openai_base_url = body.openai_base_url or "https://api.openai.com/v1"
    if body.openai_max_tokens is not None:
        gs.openai_max_tokens = max(256, min(body.openai_max_tokens, 100000))
    if body.openai_default_model is not None:
        gs.openai_default_model = body.openai_default_model or None
    if body.openai_temperature is not None:
        gs.openai_temperature = max(0.0, min(body.openai_temperature, 2.0))
    if "openai_top_p" in body.model_fields_set:
        gs.openai_top_p = body.openai_top_p
    if body.openai_frequency_penalty is not None:
        gs.openai_frequency_penalty = max(-2.0, min(body.openai_frequency_penalty, 2.0))
    if body.openai_presence_penalty is not None:
        gs.openai_presence_penalty = max(-2.0, min(body.openai_presence_penalty, 2.0))
    if body.openrouter_api_key is not None:
        gs.openrouter_api_key_enc = encrypt_value(body.openrouter_api_key) if body.openrouter_api_key else None
        # A hand-pasted key replaces whatever the OAuth connect flow stored.
        gs.openrouter_auth_method = "manual" if body.openrouter_api_key else "manual"

    if body.openrouter_base_url is not None:
        gs.openrouter_base_url = body.openrouter_base_url or "https://openrouter.ai/api/v1"
    if body.openrouter_max_tokens is not None:
        gs.openrouter_max_tokens = max(256, min(body.openrouter_max_tokens, 100000))
    if body.openrouter_default_model is not None:
        gs.openrouter_default_model = body.openrouter_default_model or None
    if body.openrouter_temperature is not None:
        gs.openrouter_temperature = max(0.0, min(body.openrouter_temperature, 2.0))
    if "openrouter_top_p" in body.model_fields_set:
        gs.openrouter_top_p = body.openrouter_top_p
    if body.mistral_api_key is not None:
        gs.mistral_api_key_enc = encrypt_value(body.mistral_api_key) if body.mistral_api_key else None
    if body.mistral_base_url is not None:
        gs.mistral_base_url = body.mistral_base_url or "https://api.mistral.ai/v1"
    if body.mistral_max_tokens is not None:
        gs.mistral_max_tokens = max(256, min(body.mistral_max_tokens, 100000))
    if body.mistral_default_model is not None:
        gs.mistral_default_model = body.mistral_default_model or None
    if body.mistral_temperature is not None:
        gs.mistral_temperature = max(0.0, min(body.mistral_temperature, 2.0))
    if "mistral_top_p" in body.model_fields_set:
        gs.mistral_top_p = body.mistral_top_p
    if body.groq_api_key is not None:
        gs.groq_api_key_enc = encrypt_value(body.groq_api_key) if body.groq_api_key else None
    if body.groq_base_url is not None:
        gs.groq_base_url = body.groq_base_url or "https://api.groq.com/openai/v1"
    if body.groq_max_tokens is not None:
        gs.groq_max_tokens = max(256, min(body.groq_max_tokens, 100000))
    if body.groq_default_model is not None:
        gs.groq_default_model = body.groq_default_model or None
    if body.groq_temperature is not None:
        gs.groq_temperature = max(0.0, min(body.groq_temperature, 2.0))
    if "groq_top_p" in body.model_fields_set:
        gs.groq_top_p = body.groq_top_p
    if body.xai_api_key is not None:
        gs.xai_api_key_enc = encrypt_value(body.xai_api_key) if body.xai_api_key else None
    if body.xai_base_url is not None:
        gs.xai_base_url = body.xai_base_url or "https://api.x.ai/v1"
    if body.xai_max_tokens is not None:
        gs.xai_max_tokens = max(256, min(body.xai_max_tokens, 100000))
    if body.xai_default_model is not None:
        gs.xai_default_model = body.xai_default_model or None
    if body.xai_temperature is not None:
        gs.xai_temperature = max(0.0, min(body.xai_temperature, 2.0))
    if "xai_top_p" in body.model_fields_set:
        gs.xai_top_p = body.xai_top_p
    if body.deepseek_api_key is not None:
        gs.deepseek_api_key_enc = encrypt_value(body.deepseek_api_key) if body.deepseek_api_key else None
    if body.deepseek_base_url is not None:
        gs.deepseek_base_url = body.deepseek_base_url or "https://api.deepseek.com"
    if body.deepseek_max_tokens is not None:
        gs.deepseek_max_tokens = max(256, min(body.deepseek_max_tokens, 100000))
    if body.deepseek_default_model is not None:
        gs.deepseek_default_model = body.deepseek_default_model or None
    if body.deepseek_temperature is not None:
        gs.deepseek_temperature = max(0.0, min(body.deepseek_temperature, 2.0))
    if "deepseek_top_p" in body.model_fields_set:
        gs.deepseek_top_p = body.deepseek_top_p
    if body.kimi_api_key is not None:
        gs.kimi_api_key_enc = encrypt_value(body.kimi_api_key) if body.kimi_api_key else None
    if body.kimi_base_url is not None:
        gs.kimi_base_url = body.kimi_base_url or "https://api.moonshot.ai/v1"
    if body.kimi_max_tokens is not None:
        gs.kimi_max_tokens = max(256, min(body.kimi_max_tokens, 100000))
    if body.kimi_default_model is not None:
        gs.kimi_default_model = body.kimi_default_model or None
    if body.kimi_temperature is not None:
        gs.kimi_temperature = max(0.0, min(body.kimi_temperature, 2.0))
    if "kimi_top_p" in body.model_fields_set:
        gs.kimi_top_p = body.kimi_top_p
    if body.zai_api_key is not None:
        gs.zai_api_key_enc = encrypt_value(body.zai_api_key) if body.zai_api_key else None
    if body.zai_base_url is not None:
        gs.zai_base_url = body.zai_base_url or "https://api.z.ai/api/paas/v4"
    if body.zai_max_tokens is not None:
        gs.zai_max_tokens = max(256, min(body.zai_max_tokens, 100000))
    if body.zai_default_model is not None:
        gs.zai_default_model = body.zai_default_model or None
    if body.zai_temperature is not None:
        gs.zai_temperature = max(0.0, min(body.zai_temperature, 2.0))
    if "zai_top_p" in body.model_fields_set:
        gs.zai_top_p = body.zai_top_p
    if body.ollama_mode is not None:
        if body.ollama_mode not in ("local", "cloud"):
            raise HTTPException(status_code=422, detail="ollama_mode must be 'local' or 'cloud'")
        gs.ollama_mode = body.ollama_mode
    if body.ollama_api_key is not None:
        gs.ollama_api_key_enc = encrypt_value(body.ollama_api_key) if body.ollama_api_key else None
    if body.ollama_base_url is not None:
        gs.ollama_base_url = body.ollama_base_url
    if body.ollama_default_model is not None:
        gs.ollama_default_model = body.ollama_default_model
    if body.ollama_temperature is not None:
        gs.ollama_temperature = body.ollama_temperature
    if body.ollama_num_ctx is not None:
        gs.ollama_num_ctx = body.ollama_num_ctx
    if body.ollama_max_tokens is not None:
        gs.ollama_max_tokens = max(64, min(body.ollama_max_tokens, 8192))
    if "ollama_top_p" in body.model_fields_set:
        gs.ollama_top_p = body.ollama_top_p
    if "ollama_top_k" in body.model_fields_set:
        gs.ollama_top_k = body.ollama_top_k
    if "ollama_repeat_penalty" in body.model_fields_set:
        gs.ollama_repeat_penalty = body.ollama_repeat_penalty
    if body.scan_max_rps is not None:
        gs.scan_max_rps = max(0.0, min(body.scan_max_rps, 100.0))
    if body.max_concurrent_scans is not None:
        gs.max_concurrent_scans = body.max_concurrent_scans
    if body.smtp_host is not None:
        gs.smtp_host = body.smtp_host
    if body.smtp_port is not None:
        gs.smtp_port = body.smtp_port
    if body.smtp_user is not None:
        gs.smtp_user = body.smtp_user
    if body.smtp_password is not None:
        gs.smtp_pass_enc = encrypt_value(body.smtp_password) if body.smtp_password else None
    if body.smtp_from is not None:
        gs.smtp_from = body.smtp_from
    if body.slack_webhook is not None:
        gs.slack_webhook_enc = encrypt_value(body.slack_webhook) if body.slack_webhook else None

    gs.updated_by = current_user.id
    await db.flush()
    return _to_settings_out(gs)


@router.post("/test-llm", response_model=TestLlmResponse)
async def test_llm(
    body: TestLlmRequest,
    current_user: User = Depends(require_min_role("admin")),
) -> TestLlmResponse:
    try:
        if body.provider == "anthropic":
            models = await validate_anthropic_key(body.api_key, body.base_url)
        elif body.provider == "openrouter":
            models = await validate_openrouter_key(body.api_key, body.base_url)
        elif body.provider in ("openai", "mistral", "groq", "xai", "deepseek", "kimi", "zai"):
            models = await validate_openai_key(body.api_key, body.base_url)
        elif body.provider == "ollama":
            url = body.ollama_url or "http://localhost:11434"
            models = await detect_ollama_models(url)
        else:
            return TestLlmResponse(valid=False, error=f"Unknown provider: {body.provider}")
        return TestLlmResponse(valid=True, models=models)
    except Exception as e:
        return TestLlmResponse(valid=False, error=str(e))


@router.post("/detect-ollama-models", response_model=list[str])
async def detect_ollama(
    body: DetectOllamaRequest,
    current_user: User = Depends(get_current_user),
) -> list[str]:
    try:
        return await detect_ollama_models(body.base_url)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cannot reach Ollama: {e}")


class ClearDataRequest(BaseModel):
    confirm: str  # Must equal "DELETE ALL DATA" to proceed


class ClearDataResult(BaseModel):
    scans_deleted: int
    findings_deleted: int
    logs_deleted: int


@router.post("/clear-data", response_model=ClearDataResult)
async def clear_all_data(
    body: ClearDataRequest,
    current_user: User = Depends(require_min_role("superadmin")),
    db: AsyncSession = Depends(get_db),
) -> ClearDataResult:
    """
    Permanently delete all scans, findings, scan logs, and reports.
    Requires superadmin role and the confirmation phrase 'DELETE ALL DATA'.
    User accounts and settings are preserved.
    """
    if body.confirm != "DELETE ALL DATA":
        raise HTTPException(status_code=400, detail="Invalid confirmation phrase")

    import os, shutil

    # Count before deletion for the summary
    scans_count = (await db.execute(text("SELECT COUNT(*) FROM scans"))).scalar_one()
    findings_count = (await db.execute(text("SELECT COUNT(*) FROM findings"))).scalar_one()
    logs_count = (await db.execute(text("SELECT COUNT(*) FROM scan_logs"))).scalar_one()

    # Delete in dependency order (children first)
    await db.execute(text("DELETE FROM finding_comments"))
    await db.execute(text("DELETE FROM findings"))
    await db.execute(text("DELETE FROM scan_logs"))
    await db.execute(text("DELETE FROM reports"))
    await db.execute(text("DELETE FROM scans"))
    await db.commit()

    # Remove evidence files from disk
    scans_dir = os.environ.get("DATA_BASE", "/app/data")
    scans_evidence_dir = os.path.join(scans_dir, "scans")
    if os.path.isdir(scans_evidence_dir):
        try:
            shutil.rmtree(scans_evidence_dir)
        except Exception:
            pass  # Non-fatal — files will be cleaned up on next scan

    return ClearDataResult(
        scans_deleted=scans_count,
        findings_deleted=findings_count,
        logs_deleted=logs_count,
    )


# ── OpenRouter OAuth (PKCE) ───────────────────────────────────────────────────
#
# OpenRouter is the only configured provider that offers a legitimate "sign in"
# path: an OAuth PKCE flow that mints a user-scoped API key for this app.
# Anthropic and OpenAI issue API keys from their consoles only — their consumer
# logins do not grant API access — and local Ollama needs no auth at all.
#
# The code→key exchange happens here rather than in the browser so the resulting
# key is encrypted server-side and never lands in frontend state.

class OpenRouterExchange(BaseModel):
    code: str
    code_verifier: str | None = None
    code_challenge_method: str = "S256"


class OpenRouterExchangeResult(BaseModel):
    connected: bool
    auth_method: str


@router.post("/openrouter/oauth-exchange", response_model=OpenRouterExchangeResult)
async def openrouter_oauth_exchange(
    body: OpenRouterExchange,
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> OpenRouterExchangeResult:
    import httpx

    payload: dict[str, str] = {"code": body.code}
    if body.code_verifier:
        payload["code_verifier"] = body.code_verifier
        payload["code_challenge_method"] = body.code_challenge_method

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/auth/keys",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach OpenRouter: {e}") from e

    if resp.status_code != 200:
        detail = resp.text[:300]
        raise HTTPException(
            status_code=400,
            detail=f"OpenRouter rejected the authorization code ({resp.status_code}): {detail}",
        )

    key = (resp.json() or {}).get("key")
    if not key:
        raise HTTPException(status_code=502, detail="OpenRouter returned no key in the response")

    gs = await _get_or_create_settings(db)
    gs.openrouter_api_key_enc = encrypt_value(key)
    gs.openrouter_auth_method = "oauth"
    if not gs.openrouter_base_url:
        gs.openrouter_base_url = "https://openrouter.ai/api/v1"
    await db.commit()

    return OpenRouterExchangeResult(connected=True, auth_method="oauth")


@router.post("/openrouter/disconnect", response_model=OpenRouterExchangeResult)
async def openrouter_disconnect(
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> OpenRouterExchangeResult:
    """Forget the stored key. The key itself stays valid on OpenRouter's side —
    revoke it from the OpenRouter dashboard to fully invalidate it."""
    gs = await _get_or_create_settings(db)
    gs.openrouter_api_key_enc = None
    gs.openrouter_auth_method = "manual"
    await db.commit()
    return OpenRouterExchangeResult(connected=False, auth_method="manual")
