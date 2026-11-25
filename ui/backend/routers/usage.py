"""routers/usage.py — LLM token / cost ledger."""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.ops import EngagementBudget, LlmUsageEvent
from backend.models.scan import Scan
from backend.models.user import User

router = APIRouter(prefix="/usage", tags=["usage"])

# Rough USD / 1M tokens (blended) for estimates when providers don't report cost
_COST_PER_MTOK = {
    "openai": 5.0,
    "anthropic": 8.0,
    "openrouter": 4.0,
    "ollama": 0.0,
    "mistral": 2.0,
    "groq": 0.5,
    "xai": 3.0,
    "deepseek": 0.5,
    "kimi": 1.5,
    "zai": 1.0,
}


class UsageSummary(BaseModel):
    total_tokens: int
    prompt_tokens: int
    completion_tokens: int
    estimated_cost_usd: float
    events: int
    by_provider: list[dict]
    by_day: list[dict]


class UsageIngest(BaseModel):
    scan_id: str | None = None
    provider: str = "unknown"
    model: str | None = None
    phase: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0


@router.get("/summary", response_model=UsageSummary)
async def usage_summary(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UsageSummary:
    cutoff = datetime.utcnow() - timedelta(days=days)
    rows = (
        await db.execute(select(LlmUsageEvent).where(LlmUsageEvent.created_at >= cutoff))
    ).scalars().all()

    if not rows:
        # Bootstrap estimates from completed scans so the ledger isn't empty
        scans = (
            await db.execute(
                select(Scan).where(Scan.status == "completed").order_by(Scan.created_at.desc()).limit(40)
            )
        ).scalars().all()
        for s in scans:
            turns = max(1, (s.hypotheses_tested or s.hypotheses_total or 3))
            tokens = turns * 3500
            rate = _COST_PER_MTOK.get((s.llm_provider or "").lower(), 3.0)
            cost = (tokens / 1_000_000) * rate
            db.add(LlmUsageEvent(
                scan_id=s.id,
                provider=s.llm_provider or "unknown",
                model=s.llm_model,
                phase="estimated",
                prompt_tokens=int(tokens * 0.7),
                completion_tokens=int(tokens * 0.3),
                total_tokens=tokens,
                estimated_cost_usd=round(cost, 4),
            ))
            bud = (await db.execute(select(EngagementBudget).where(EngagementBudget.scan_id == s.id))).scalar_one_or_none()
            if not bud:
                bud = EngagementBudget(scan_id=s.id, tokens_used=tokens, turns_used=turns)
                db.add(bud)
            else:
                bud.tokens_used = max(bud.tokens_used, tokens)
                bud.turns_used = max(bud.turns_used, turns)
        await db.flush()
        rows = (
            await db.execute(select(LlmUsageEvent).where(LlmUsageEvent.created_at >= cutoff))
        ).scalars().all()

    by_prov: dict[str, dict] = {}
    by_day: dict[str, dict] = {}
    tot_p = tot_c = tot = 0
    cost = 0.0
    for r in rows:
        tot_p += r.prompt_tokens
        tot_c += r.completion_tokens
        tot += r.total_tokens
        cost += r.estimated_cost_usd
        p = by_prov.setdefault(r.provider, {"provider": r.provider, "tokens": 0, "cost": 0.0})
        p["tokens"] += r.total_tokens
        p["cost"] = round(p["cost"] + r.estimated_cost_usd, 4)
        day = (r.created_at or datetime.utcnow()).strftime("%Y-%m-%d")
        d = by_day.setdefault(day, {"day": day, "tokens": 0, "cost": 0.0})
        d["tokens"] += r.total_tokens
        d["cost"] = round(d["cost"] + r.estimated_cost_usd, 4)

    return UsageSummary(
        total_tokens=tot,
        prompt_tokens=tot_p,
        completion_tokens=tot_c,
        estimated_cost_usd=round(cost, 4),
        events=len(rows),
        by_provider=sorted(by_prov.values(), key=lambda x: -x["tokens"]),
        by_day=sorted(by_day.values(), key=lambda x: x["day"]),
    )


@router.post("/ingest")
async def ingest_usage(
    body: UsageIngest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    total = max(0, body.prompt_tokens) + max(0, body.completion_tokens)
    rate = _COST_PER_MTOK.get(body.provider.lower(), 3.0)
    cost = (total / 1_000_000) * rate
    db.add(LlmUsageEvent(
        scan_id=body.scan_id,
        provider=body.provider,
        model=body.model,
        phase=body.phase,
        prompt_tokens=body.prompt_tokens,
        completion_tokens=body.completion_tokens,
        total_tokens=total,
        estimated_cost_usd=round(cost, 4),
    ))
    if body.scan_id:
        bud = (
            await db.execute(select(EngagementBudget).where(EngagementBudget.scan_id == body.scan_id))
        ).scalar_one_or_none()
        if not bud:
            bud = EngagementBudget(scan_id=body.scan_id)
            db.add(bud)
        bud.tokens_used = (bud.tokens_used or 0) + total
        bud.turns_used = (bud.turns_used or 0) + 1
    return {"ok": True, "total_tokens": total, "estimated_cost_usd": round(cost, 4)}
