"""routers/approvals.py — Human-in-the-loop intercept queue."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.ops import ApprovalRequest, EngagementBudget
from backend.models.scan import Scan
from backend.models.user import User

router = APIRouter(prefix="/approvals", tags=["approvals"])


class ApprovalOut(BaseModel):
    id: str
    scan_id: str | None
    action: str
    detail: str | None
    risk: str
    status: str
    decided_by: str | None
    decided_at: datetime | None
    created_at: datetime
    target_url: str | None = None

    model_config = {"from_attributes": True}


class ApprovalCreate(BaseModel):
    scan_id: str | None = None
    action: str = Field(..., min_length=2, max_length=128)
    detail: str | None = None
    risk: str = "medium"


class DecisionBody(BaseModel):
    note: str | None = None


class BudgetOut(BaseModel):
    scan_id: str
    token_budget: int
    turn_budget: int
    tokens_used: int
    turns_used: int
    hitl_required: bool
    scope_deny: list[str] = []
    token_pct: float
    turn_pct: float
    wrap_up: bool


class BudgetUpdate(BaseModel):
    token_budget: int | None = None
    turn_budget: int | None = None
    hitl_required: bool | None = None
    scope_deny: list[str] | None = None


def _deny_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    import json
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else []
    except Exception:
        return [x.strip() for x in raw.split("\n") if x.strip()]


@router.get("", response_model=list[ApprovalOut])
async def list_approvals(
    status: str | None = Query("pending"),
    limit: int = Query(50, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ApprovalOut]:
    stmt = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(ApprovalRequest.status == status)
    rows = (await db.execute(stmt)).scalars().all()
    scan_ids = {r.scan_id for r in rows if r.scan_id}
    targets: dict[str, str] = {}
    if scan_ids:
        for s in (await db.execute(select(Scan).where(Scan.id.in_(scan_ids)))).scalars().all():
            targets[s.id] = s.target_url
    out = []
    for r in rows:
        item = ApprovalOut.model_validate(r)
        item.target_url = targets.get(r.scan_id or "")
        out.append(item)
    return out


@router.get("/summary")
async def approvals_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    pending = (
        await db.execute(
            select(func.count()).select_from(ApprovalRequest).where(ApprovalRequest.status == "pending")
        )
    ).scalar_one()
    return {"pending": pending}


@router.post("", response_model=ApprovalOut)
async def create_approval(
    body: ApprovalCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ApprovalOut:
    row = ApprovalRequest(
        scan_id=body.scan_id,
        action=body.action,
        detail=body.detail,
        risk=body.risk if body.risk in ("low", "medium", "high", "critical") else "medium",
    )
    db.add(row)
    await db.flush()
    return ApprovalOut.model_validate(row)


@router.post("/{approval_id}/approve", response_model=ApprovalOut)
async def approve(
    approval_id: str,
    body: DecisionBody | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ApprovalOut:
    row = (await db.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Approval not found")
    if row.status != "pending":
        raise HTTPException(400, f"Already {row.status}")
    row.status = "approved"
    row.decided_by = current_user.username
    row.decided_at = datetime.utcnow()
    if body and body.note:
        row.detail = (row.detail or "") + f"\n[approve note] {body.note}"
    await db.flush()
    return ApprovalOut.model_validate(row)


@router.post("/{approval_id}/deny", response_model=ApprovalOut)
async def deny(
    approval_id: str,
    body: DecisionBody | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ApprovalOut:
    row = (await db.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Approval not found")
    if row.status != "pending":
        raise HTTPException(400, f"Already {row.status}")
    row.status = "denied"
    row.decided_by = current_user.username
    row.decided_at = datetime.utcnow()
    if body and body.note:
        row.detail = (row.detail or "") + f"\n[deny note] {body.note}"
    await db.flush()
    return ApprovalOut.model_validate(row)


@router.post("/seed-demo")
async def seed_demo_approvals(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create sample pending approvals from running/recent scans (demo / ops bootstrap)."""
    scans = (
        await db.execute(
            select(Scan).where(Scan.status.in_(["running", "queued", "completed"]))
            .order_by(Scan.created_at.desc()).limit(5)
        )
    ).scalars().all()
    pending = (
        await db.execute(
            select(func.count()).select_from(ApprovalRequest).where(ApprovalRequest.status == "pending")
        )
    ).scalar_one()
    if pending > 0 or not scans:
        return {"created": 0, "reason": "already_has_pending_or_no_scans"}

    samples = [
        ("SQLMap --batch against auth endpoint", "high", "Destructive / noisy DB probe"),
        ("Password spray on /login", "critical", "Credential stuffing against live users"),
        ("Delete test account via admin API", "high", "State-changing admin action"),
    ]
    created = 0
    for i, scan in enumerate(scans[:3]):
        action, risk, detail = samples[i % len(samples)]
        db.add(ApprovalRequest(
            scan_id=scan.id,
            action=action,
            detail=f"{detail}\nTarget: {scan.target_url}",
            risk=risk,
        ))
        created += 1
    return {"created": created}


@router.get("/budgets/{scan_id}", response_model=BudgetOut)
async def get_budget(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> BudgetOut:
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    row = (await db.execute(select(EngagementBudget).where(EngagementBudget.scan_id == scan_id))).scalar_one_or_none()
    if not row:
        row = EngagementBudget(scan_id=scan_id)
        db.add(row)
        await db.flush()
    token_pct = min(100.0, (row.tokens_used / max(row.token_budget, 1)) * 100)
    turn_pct = min(100.0, (row.turns_used / max(row.turn_budget, 1)) * 100)
    return BudgetOut(
        scan_id=row.scan_id,
        token_budget=row.token_budget,
        turn_budget=row.turn_budget,
        tokens_used=row.tokens_used,
        turns_used=row.turns_used,
        hitl_required=row.hitl_required,
        scope_deny=_deny_list(row.scope_deny),
        token_pct=round(token_pct, 1),
        turn_pct=round(turn_pct, 1),
        wrap_up=token_pct >= 90 or turn_pct >= 90,
    )


@router.put("/budgets/{scan_id}", response_model=BudgetOut)
async def update_budget(
    scan_id: str,
    body: BudgetUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> BudgetOut:
    import json
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    row = (await db.execute(select(EngagementBudget).where(EngagementBudget.scan_id == scan_id))).scalar_one_or_none()
    if not row:
        row = EngagementBudget(scan_id=scan_id)
        db.add(row)
    if body.token_budget is not None:
        row.token_budget = max(1000, body.token_budget)
    if body.turn_budget is not None:
        row.turn_budget = max(1, body.turn_budget)
    if body.hitl_required is not None:
        row.hitl_required = body.hitl_required
    if body.scope_deny is not None:
        row.scope_deny = json.dumps(body.scope_deny)
    await db.flush()
    token_pct = min(100.0, (row.tokens_used / max(row.token_budget, 1)) * 100)
    turn_pct = min(100.0, (row.turns_used / max(row.turn_budget, 1)) * 100)
    return BudgetOut(
        scan_id=row.scan_id,
        token_budget=row.token_budget,
        turn_budget=row.turn_budget,
        tokens_used=row.tokens_used,
        turns_used=row.turns_used,
        hitl_required=row.hitl_required,
        scope_deny=_deny_list(row.scope_deny),
        token_pct=round(token_pct, 1),
        turn_pct=round(turn_pct, 1),
        wrap_up=token_pct >= 90 or turn_pct >= 90,
    )
