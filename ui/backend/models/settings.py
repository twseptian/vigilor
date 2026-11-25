"""models/settings.py — Global settings singleton and notification channels."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class GlobalSettings(Base):
    """Singleton row (id=1) storing encrypted credentials and system config."""

    __tablename__ = "global_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    # LLM credentials (AES-256 encrypted at rest)
    anthropic_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    anthropic_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.anthropic.com")
    anthropic_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    openai_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    openai_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.openai.com/v1")
    openai_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    openai_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    openrouter_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "manual" = key pasted by the user, "oauth" = obtained via OpenRouter PKCE
    openrouter_auth_method: Mapped[str | None] = mapped_column(String(16), nullable=True, default="manual")
    openrouter_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://openrouter.ai/api/v1")
    openrouter_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    openrouter_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    opencode_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    opencode_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.opencode.ai/v1")
    opencode_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    opencode_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # OpenAI-compatible providers (share the OpenAIEngine via OPENAI_* env vars)
    mistral_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    mistral_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.mistral.ai/v1")
    mistral_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    mistral_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    mistral_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    mistral_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    groq_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    groq_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.groq.com/openai/v1")
    groq_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    groq_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    groq_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    groq_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    xai_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    xai_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.x.ai/v1")
    xai_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    xai_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    xai_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    xai_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    deepseek_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    deepseek_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.deepseek.com")
    deepseek_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    deepseek_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    deepseek_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    deepseek_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    kimi_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    kimi_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.moonshot.ai/v1")
    kimi_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    kimi_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    kimi_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    kimi_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Z.AI (GLM) — OpenAI-compatible at https://api.z.ai/api/paas/v4
    zai_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    zai_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.z.ai/api/paas/v4")
    zai_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    zai_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    zai_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    zai_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Anthropic advanced
    anthropic_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    anthropic_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    # OpenAI advanced
    openai_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    openai_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    openai_frequency_penalty: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    openai_presence_penalty: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    # OpenRouter advanced
    openrouter_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.7)
    openrouter_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Ollama
    # "local" = self-hosted Ollama, no auth. "cloud" = ollama.com, API key required.
    ollama_mode: Mapped[str | None] = mapped_column(String(16), nullable=True, default="local")
    ollama_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    ollama_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="http://localhost:11434")
    ollama_default_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ollama_temperature: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.1)
    ollama_num_ctx: Mapped[int | None] = mapped_column(Integer, nullable=True, default=8192)
    ollama_max_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True, default=512)
    ollama_top_p: Mapped[float | None] = mapped_column(Float, nullable=True)
    ollama_top_k: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ollama_repeat_penalty: Mapped[float | None] = mapped_column(Float, nullable=True)

    # SMTP
    smtp_host: Mapped[str | None] = mapped_column(String(256), nullable=True)
    smtp_port: Mapped[int | None] = mapped_column(Integer, nullable=True, default=587)
    smtp_user: Mapped[str | None] = mapped_column(String(256), nullable=True)
    smtp_pass_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    smtp_from: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Slack
    slack_webhook_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # System
    # Outbound pacing: max requests/second the engine may generate. 0 = unlimited.
    scan_max_rps: Mapped[float | None] = mapped_column(Float, nullable=True, default=0)
    max_concurrent_scans: Mapped[int] = mapped_column(Integer, default=3)
    report_retention_days: Mapped[int] = mapped_column(Integer, default=90)

    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    type: Mapped[str] = mapped_column(
        String(32), nullable=False  # "email" | "slack" | "webhook" | "teams"
    )
    config: Mapped[str] = mapped_column(Text, nullable=False)   # JSON
    events: Mapped[str] = mapped_column(Text, nullable=False)   # JSON list of event types
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_name: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
