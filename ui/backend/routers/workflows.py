"""routers/workflows.py — Attack workflow (attack chain / exploitation flow) endpoints.

  GET  /scans/{scan_id}/workflow        — scan-level attack chain graph (lazily built)
  POST /scans/{scan_id}/workflow        — (re)generate, optionally with LLM narrative
  GET  /findings/{finding_id}/workflow  — per-finding exploitation flow (lazily built)
  POST /findings/{finding_id}/workflow  — (re)generate the per-finding flow
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user, require_min_role
from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.models.user import User
from backend.models.workflow import AttackWorkflow
from backend.services import attack_workflow as awf

router = APIRouter(tags=["workflows"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class WorkflowOut(BaseModel):
    id: str
    scan_id: str
    finding_id: str | None
    kind: str
    generator: str
    llm_model: str | None
    summary: str
    graph: dict[str, Any]
    chains: list[dict[str, Any]]
    mermaid: str
    node_count: int
    edge_count: int
    chain_count: int
    stages: list[dict[str, str]]
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _load_row(db: AsyncSession, scan_id: str, finding_id: str | None) -> AttackWorkflow | None:
    stmt = select(AttackWorkflow).where(AttackWorkflow.scan_id == scan_id)
    stmt = stmt.where(
        AttackWorkflow.finding_id.is_(None) if finding_id is None
        else AttackWorkflow.finding_id == finding_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def _scan_findings(db: AsyncSession, scan_id: str) -> list[Finding]:
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return list(result.scalars().all())


async def _build_engine(db: AsyncSession, scan: Scan) -> Any | None:
    """Construct the scan's LLM engine, or None when it cannot be initialised."""
    try:
        from backend.models.settings import GlobalSettings
        from backend.services.scan_runner import create_engine_for_scan

        gs = await db.get(GlobalSettings, 1)
        return create_engine_for_scan(scan, gs)
    except Exception:
        return None


async def _generate_scan_workflow(
    db: AsyncSession, scan: Scan, use_llm: bool
) -> AttackWorkflow:
    findings = await _scan_findings(db, scan.id)
    engine = await _build_engine(db, scan) if use_llm else None
    workflow = await awf.build_scan_workflow(scan, findings, engine)
    return await awf.save_workflow(db, scan.id, None, workflow)


# ── Scan-level workflow ───────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/workflow", response_model=WorkflowOut)
async def get_scan_workflow(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> WorkflowOut:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    row = await _load_row(db, scan_id, None)
    if row is None:
        # Build on first view (rules only — no LLM tokens spent on a plain GET)
        row = await _generate_scan_workflow(db, scan, use_llm=False)
    return WorkflowOut(**awf.row_to_dict(row))


@router.post("/scans/{scan_id}/workflow", response_model=WorkflowOut)
async def generate_scan_workflow(
    scan_id: str,
    use_llm: bool = Query(True, description="Let the scan's LLM write the narrative and propose extra chains"),
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> WorkflowOut:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    row = await _generate_scan_workflow(db, scan, use_llm=use_llm)
    return WorkflowOut(**awf.row_to_dict(row))


# ── Per-finding workflow ──────────────────────────────────────────────────────

@router.get("/findings/{finding_id}/workflow", response_model=WorkflowOut)
async def get_finding_workflow(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> WorkflowOut:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    row = await _load_row(db, finding.scan_id, finding_id)
    if row is None:
        workflow = awf.build_finding_flow(scan, finding)
        row = await awf.save_workflow(db, finding.scan_id, finding_id, workflow)
    return WorkflowOut(**awf.row_to_dict(row))


@router.post("/findings/{finding_id}/workflow", response_model=WorkflowOut)
async def generate_finding_workflow(
    finding_id: str,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> WorkflowOut:
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    workflow = awf.build_finding_flow(scan, finding)
    row = await awf.save_workflow(db, finding.scan_id, finding_id, workflow)
    return WorkflowOut(**awf.row_to_dict(row))
