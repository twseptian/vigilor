"""models/workflow.py — AttackWorkflow model.

Stores the generated attack workflow for a scan (cross-finding attack chains)
or for a single finding (step-by-step exploitation flow).

One row per (scan_id, finding_id) pair:
  finding_id IS NULL  → scan-level workflow  (kind="scan")
  finding_id set      → per-finding flow     (kind="finding")
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base

if TYPE_CHECKING:
    from backend.models.scan import Scan


class AttackWorkflow(Base):
    __tablename__ = "attack_workflows"
    __table_args__ = (
        UniqueConstraint("scan_id", "finding_id", name="uq_attack_workflow_scan_finding"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )

    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="scan")  # scan | finding

    # How the workflow was produced: "heuristic" (rules only) or "heuristic+llm"
    generator: Mapped[str] = mapped_column(String(32), nullable=False, default="heuristic")
    llm_model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    summary: Mapped[str | None] = mapped_column(Text, nullable=True)      # narrative
    graph_json: Mapped[str | None] = mapped_column(Text, nullable=True)   # {"nodes":[…],"edges":[…]}
    chains_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # [{…chain…}]
    mermaid: Mapped[str | None] = mapped_column(Text, nullable=True)      # mermaid flowchart source

    node_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    edge_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    chain_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    scan: Mapped["Scan"] = relationship()

    def __repr__(self) -> str:
        return f"<AttackWorkflow {self.kind} scan={self.scan_id} chains={self.chain_count}>"
