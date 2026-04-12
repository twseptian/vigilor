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
)

router = APIRouter(prefix="/settings", tags=["settings"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class SettingsOut(BaseModel):
    anthropic_key_set: bool
    anthropic_base_url: str | None
    anthropic_max_tokens: int
    openai_key_set: bool
    openai_base_url: str | None
    openai_max_tokens: int
    openai_default_model: str | None
    openrouter_key_set: bool
    openrouter_base_url: str | None
    openrouter_max_tokens: int
    openrouter_default_model: str | None
    ollama_base_url: str | None
    ollama_default_model: str | None
    ollama_temperature: float | None
    ollama_num_ctx: int | None
    ollama_max_tokens: int | None
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
    openai_api_key: str | None = None
    openai_base_url: str | None = None
    openai_max_tokens: int | None = None
    openai_default_model: str | None = None
    openrouter_api_key: str | None = None
    openrouter_base_url: str | None = None
    openrouter_max_tokens: int | None = None
    openrouter_default_model: str | None = None
    ollama_base_url: str | None = None
    ollama_default_model: str | None = None
    ollama_temperature: float | None = None
    ollama_num_ctx: int | None = None
    ollama_max_tokens: int | None = None
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
        openai_key_set=bool(gs.openai_api_key_enc),
        openai_base_url=gs.openai_base_url or "https://api.openai.com",
        openai_max_tokens=gs.openai_max_tokens or 4096,
        openai_default_model=gs.openai_default_model,
        openrouter_key_set=bool(gs.openrouter_api_key_enc),
        openrouter_base_url=gs.openrouter_base_url or "https://openrouter.ai/api/v1",
        openrouter_max_tokens=gs.openrouter_max_tokens or 4096,
        openrouter_default_model=gs.openrouter_default_model,
        ollama_base_url=gs.ollama_base_url,
        ollama_default_model=gs.ollama_default_model,
        ollama_temperature=gs.ollama_temperature,
        ollama_num_ctx=gs.ollama_num_ctx,
        ollama_max_tokens=gs.ollama_max_tokens,
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
    if body.openai_api_key is not None:
        gs.openai_api_key_enc = encrypt_value(body.openai_api_key) if body.openai_api_key else None
    if body.openai_base_url is not None:
        gs.openai_base_url = body.openai_base_url or "https://api.openai.com"
    if body.openai_max_tokens is not None:
        gs.openai_max_tokens = max(256, min(body.openai_max_tokens, 100000))
    if body.openai_default_model is not None:
        gs.openai_default_model = body.openai_default_model or None
    if body.openrouter_api_key is not None:
        gs.openrouter_api_key_enc = encrypt_value(body.openrouter_api_key) if body.openrouter_api_key else None
    if body.openrouter_base_url is not None:
        gs.openrouter_base_url = body.openrouter_base_url or "https://openrouter.ai/api/v1"
    if body.openrouter_max_tokens is not None:
        gs.openrouter_max_tokens = max(256, min(body.openrouter_max_tokens, 100000))
    if body.openrouter_default_model is not None:
        gs.openrouter_default_model = body.openrouter_default_model or None
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
        elif body.provider in ("openai", "openrouter"):
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
