"""models/scan.py — Scan, ScanLog, and ScanSchedule models."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, Enum, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base

if TYPE_CHECKING:
    from backend.models.project import Project
    from backend.models.finding import Finding
    from backend.models.report import Report


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)

    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scan_mode: Mapped[str] = mapped_column(
        Enum("full", "static_only", name="scan_mode"), nullable=False, default="full"
    )
    llm_provider: Mapped[str] = mapped_column(
        String(32), nullable=False, default="anthropic"
    )
    llm_model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    status: Mapped[str] = mapped_column(
        Enum("queued", "running", "completed", "failed", "cancelled", name="scan_status"),
        nullable=False,
        default="queued",
        index=True,
    )
    phase: Mapped[str | None] = mapped_column(String(32), nullable=True)
    phase_detail: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Scan configuration
    scope_include: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON array
    scope_exclude: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON array
    headers: Mapped[str | None] = mapped_column(Text, nullable=True)         # JSON object
    cookies: Mapped[str | None] = mapped_column(Text, nullable=True)         # JSON object
    max_hypotheses: Mapped[int] = mapped_column(Integer, default=8)
    max_parallel: Mapped[int] = mapped_column(Integer, default=3)
    feedback_iter: Mapped[int] = mapped_column(Integer, default=2)
    repo_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    custom_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Findings summary (denormalized for fast list views)
    findings_critical: Mapped[int] = mapped_column(Integer, default=0)
    findings_high: Mapped[int] = mapped_column(Integer, default=0)
    findings_medium: Mapped[int] = mapped_column(Integer, default=0)
    findings_low: Mapped[int] = mapped_column(Integer, default=0)
    findings_info: Mapped[int] = mapped_column(Integer, default=0)
    hypotheses_total: Mapped[int] = mapped_column(Integer, default=0)
    hypotheses_confirmed: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    trace_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # relationships
    project: Mapped["Project | None"] = relationship(back_populates="scans")
    logs: Mapped[list["ScanLog"]] = relationship(back_populates="scan", cascade="all, delete-orphan", order_by="ScanLog.id")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan {self.target_url} [{self.status}]>"


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    level: Mapped[str] = mapped_column(String(10), nullable=False, default="INFO")
    phase: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    message: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="logs")


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    cron_expr: Mapped[str] = mapped_column(String(64), nullable=False)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scan_config: Mapped[str] = mapped_column(Text, nullable=False)   # JSON

    is_active: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
