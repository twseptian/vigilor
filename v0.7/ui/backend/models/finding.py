"""models/finding.py — Finding and FindingComment models."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base

if TYPE_CHECKING:
    from backend.models.scan import Scan


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_ref: Mapped[str | None] = mapped_column(String(16), nullable=True)  # e.g. WVAPT-1

    title: Mapped[str] = mapped_column(String(256), nullable=False)
    vuln_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(
        Enum("Critical", "High", "Medium", "Low", "Informational", name="severity"),
        nullable=False,
        default="Medium",
        index=True,
    )
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cvss4_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss4_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)

    status: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="Open",
        index=True,
    )

    location: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    proof_of_concept: Mapped[str | None] = mapped_column(Text, nullable=True)
    implications: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)

    owasp_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    cve: Mapped[str | None] = mapped_column(String(32), nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of URLs

    screenshot_before: Mapped[str | None] = mapped_column(String(512), nullable=True)
    screenshot_after: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    comments: Mapped[list["FindingComment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingComment.created_at"
    )

    def __repr__(self) -> str:
        return f"<Finding [{self.severity}] {self.title}>"


class FindingComment(Base):
    __tablename__ = "finding_comments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    author_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    author_name: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow
    )

    finding: Mapped["Finding"] = relationship(back_populates="comments")
