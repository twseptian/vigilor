"""routers/activity.py — Broadcast timeline for the VIGILOR ops console."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.models.user import User

router = APIRouter(prefix="/activity", tags=["activity"])

Kind = Literal["goal", "intent", "fact", "finding", "phase", "digest"]


class BroadcastEvent(BaseModel):
    id: str
    kind: Kind
    ts: datetime
    title: str
    detail: str
    scan_id: str | None
    target_url: str | None
    severity: str | None = None


@router.get("/broadcast", response_model=list[BroadcastEvent])
async def broadcast(
    limit: int = Query(80, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[BroadcastEvent]:
    events: list[BroadcastEvent] = []

    scans = (
        await db.execute(
            select(Scan).order_by(Scan.created_at.desc()).limit(40)
        )
    ).scalars().all()

    for scan in scans:
        ts = scan.started_at or scan.created_at or datetime.utcnow()
        events.append(
            BroadcastEvent(
                id=f"scan-goal-{scan.id}",
                kind="goal",
                ts=ts,
                title=f"Engagement goal · {scan.status}",
                detail=f"Target {scan.target_url} · provider {scan.llm_provider}"
                + (f"/{scan.llm_model}" if scan.llm_model else ""),
                scan_id=scan.id,
                target_url=scan.target_url,
            )
        )
        if scan.phase:
            events.append(
                BroadcastEvent(
                    id=f"scan-phase-{scan.id}-{scan.phase}",
                    kind="phase",
                    ts=scan.completed_at or scan.started_at or scan.created_at or datetime.utcnow(),
                    title=f"Phase · {scan.phase}",
                    detail=scan.phase_detail or f"Scan {scan.id[:8]} is in {scan.phase}",
                    scan_id=scan.id,
                    target_url=scan.target_url,
                )
            )
        if scan.status == "completed":
            events.append(
                BroadcastEvent(
                    id=f"scan-digest-{scan.id}",
                    kind="digest",
                    ts=scan.completed_at or scan.created_at or datetime.utcnow(),
                    title="Engagement digest",
                    detail=(
                        f"C{scan.findings_critical or 0} H{scan.findings_high or 0} "
                        f"M{scan.findings_medium or 0} L{scan.findings_low or 0} "
                        f"· hypotheses {scan.hypotheses_confirmed or 0}/{scan.hypotheses_total or 0}"
                    ),
                    scan_id=scan.id,
                    target_url=scan.target_url,
                )
            )

    findings = (
        await db.execute(
            select(Finding)
            .options(selectinload(Finding.scan))
            .order_by(Finding.created_at.desc())
            .limit(50)
        )
    ).scalars().all()

    for f in findings:
        scan = getattr(f, "scan", None)
        events.append(
            BroadcastEvent(
                id=f"finding-{f.id}",
                kind="finding",
                ts=f.created_at or datetime.utcnow(),
                title=f.title,
                detail=(f.location or f.vuln_type or "Finding recorded")
                + (f" · {f.verification_status}" if f.verification_status else ""),
                scan_id=f.scan_id,
                target_url=getattr(scan, "target_url", None) if scan else None,
                severity=f.severity,
            )
        )
        if f.has_poc:
            events.append(
                BroadcastEvent(
                    id=f"fact-{f.id}",
                    kind="fact",
                    ts=f.created_at or datetime.utcnow(),
                    title="Evidence bound",
                    detail=f"PoC / request-response attached for «{f.title}»",
                    scan_id=f.scan_id,
                    target_url=getattr(scan, "target_url", None) if scan else None,
                    severity=f.severity,
                )
            )

    events.sort(key=lambda e: e.ts or datetime.min, reverse=True)
    return events[:limit]
