"""ops.py — Traffic store, HITL approvals, and LLM usage ledger (ARTEX-inspired)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class TrafficExchange(Base):
    """Captured HTTP exchange bound to a scan/finding (traffic inspector)."""

    __tablename__ = "traffic_exchanges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    url: Mapped[str] = mapped_column(String(4096), nullable=False)
    host: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    request_headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="finding")  # finding|extension|agent|manual
    tags: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), default=datetime.utcnow)


class ApprovalRequest(Base):
    """Human-in-the-loop gate for risky autonomous actions."""

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")  # low|medium|high|critical
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)  # pending|approved|denied
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), default=datetime.utcnow)


class LlmUsageEvent(Base):
    """Token / cost ledger rows for ops analytics."""

    __tablename__ = "llm_usage_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    phase: Mapped[str | None] = mapped_column(String(32), nullable=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), default=datetime.utcnow)


class EngagementBudget(Base):
    """Per-scan autonomy brakes: token + turn budgets."""

    __tablename__ = "engagement_budgets"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_budget: Mapped[int] = mapped_column(Integer, default=200_000)
    turn_budget: Mapped[int] = mapped_column(Integer, default=80)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    turns_used: Mapped[int] = mapped_column(Integer, default=0)
    hitl_required: Mapped[bool] = mapped_column(Boolean, default=True)
    scope_deny: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of deny patterns
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=datetime.utcnow)
