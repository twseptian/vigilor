"""models/settings.py — Global settings singleton and notification channels."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
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
    openai_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.openai.com")
    openai_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    openai_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    openrouter_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    openrouter_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://openrouter.ai/api/v1")
    openrouter_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    openrouter_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    opencode_api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    opencode_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="https://api.opencode.ai/v1")
    opencode_max_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4096)
    opencode_default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ollama_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True, default="http://localhost:11434")
    ollama_default_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ollama_temperature: Mapped[float | None] = mapped_column(nullable=True, default=0.1)
    ollama_num_ctx: Mapped[int | None] = mapped_column(Integer, nullable=True, default=8192)
    ollama_max_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True, default=512)

    # SMTP
    smtp_host: Mapped[str | None] = mapped_column(String(256), nullable=True)
    smtp_port: Mapped[int | None] = mapped_column(Integer, nullable=True, default=587)
    smtp_user: Mapped[str | None] = mapped_column(String(256), nullable=True)
    smtp_pass_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    smtp_from: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Slack
    slack_webhook_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # System
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
