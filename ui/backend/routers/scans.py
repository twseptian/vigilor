"""routers/scans.py — Scan CRUD, control (start/cancel/rerun), logs."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status, Response
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user, require_min_role
from backend.models.scan import Scan, ScanLog
from backend.models.user import User

# ── SSRF guard ────────────────────────────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_target_url(url: str) -> None:
    """Raise HTTPException 422 if the URL resolves to a private/loopback address."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(status_code=422, detail="target_url must use http or https")
        hostname = parsed.hostname
        if not hostname:
            raise HTTPException(status_code=422, detail="target_url must contain a hostname")
        # Resolve DNS — use getaddrinfo to support IPv6
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            for net in _PRIVATE_NETWORKS:
                if addr in net:
                    raise HTTPException(
                        status_code=422,
                        detail=f"target_url resolves to a private/reserved address ({addr})",
                    )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Cannot resolve target_url hostname: {exc}") from exc

_ALLOWED_REPO_HOSTS = ("github.com", "www.github.com", "gitlab.com", "www.gitlab.com")


def _validate_repo_url(url: str) -> str:
    """Validate a public GitHub/GitLab repo URL for Source Code Review. Returns the
    normalised clone URL. Rejects non-https, non-allowed hosts, and obvious SSRF /
    local-path attempts. Only github.com and gitlab.com are permitted (MVP: public)."""
    try:
        parsed = urlparse(url.strip())
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid repository URL: {exc}") from exc
    if parsed.scheme != "https":
        raise HTTPException(status_code=422, detail="Repository URL must use https://")
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_REPO_HOSTS:
        raise HTTPException(
            status_code=422,
            detail="Only public github.com and gitlab.com repositories are supported.",
        )
    if not parsed.path.strip("/"):
        raise HTTPException(status_code=422, detail="Repository URL must include owner/repo path.")
    # Strip credentials if a user pasted https://user:token@host/... (MVP is public only).
    clean = f"https://{host}{parsed.path}"
    if not clean.endswith(".git"):
        clean += ".git"
    return clean


router = APIRouter(prefix="/scans", tags=["scans"])

# ── Active scan tasks (scan_id → asyncio.Task) ───────────────────────────────
_active_tasks: dict[str, asyncio.Task] = {}

# ── Cancel flags (scan_id → Event) — checked at each phase boundary ──────────
_cancel_flags: dict[str, asyncio.Event] = {}


def get_cancel_flag(scan_id: str) -> asyncio.Event:
    if scan_id not in _cancel_flags:
        _cancel_flags[scan_id] = asyncio.Event()
    return _cancel_flags[scan_id]


# ── Schemas ───────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    target_url: str
    scan_mode: str = "full"
    llm_provider: str = "openai"
    llm_model: str | None = None
    project_id: str | None = None
    scope_include: list[str] = []
    scope_exclude: list[str] = []
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    max_hypotheses: int = 8
    max_parallel: int = 3
    feedback_iter: int = 2
    exploit_hypo_timeout: int = 240
    exploit_max_turns: int = 8
    exploit_hypo_cap: int = 25
    repo_path: str | None = None
    # Source Code Review: a public GitHub/GitLab repo URL. When set, the backend
    # clones it and runs static + LLM analysis on the code instead of a live crawl.
    source_repo_url: str | None = None
    custom_prompt: str | None = None
    target_description: str | None = None
    token_budget: int = 200_000
    turn_budget: int = 80
    hitl_required: bool = True
    scope_deny: list[str] = []


class ScanOut(BaseModel):
    id: str
    target_url: str
    scan_mode: str
    llm_provider: str
    llm_model: str | None
    status: str
    phase: str | None
    phase_detail: str | None
    project_id: str | None
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    findings_info: int
    hypotheses_total: int
    hypotheses_confirmed: int
    hypotheses_tested: int = 0
    duration_seconds: float | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    error_message: str | None
    source_repo_url: str | None = None
    custom_prompt: str | None = None
    target_description: str | None = None
    max_hypotheses: int = 8
    max_parallel: int = 3
    feedback_iter: int = 2
    exploit_hypo_timeout: int = 240
    exploit_max_turns: int = 8
    exploit_hypo_cap: int = 25

    model_config = {"from_attributes": True}


class ScanLogOut(BaseModel):
    id: int
    ts: datetime
    level: str
    phase: str
    message: str

    model_config = {"from_attributes": True}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ScanOut])
async def list_scans(
    status: str | None = Query(None),
    project_id: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ScanOut]:
    q = select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    if status:
        q = q.where(Scan.status == status)
    if project_id:
        q = q.where(Scan.project_id == project_id)
    result = await db.execute(q)
    return [ScanOut.model_validate(s) for s in result.scalars().all()]



async def _validate_provider_configured(db: AsyncSession, provider: str) -> None:
    """
    Refuse a scan whose LLM provider has no usable credentials.

    Without this the scan is accepted, queued, and only dies at engine init with
    "OPENAI_API_KEY is not set" — after the user has left the form, and with an
    empty Scan Output to look at. Fail at submit time instead, where the fix
    (open Settings) is one click away.
    """
    from backend.models.settings import GlobalSettings

    gs = await db.get(GlobalSettings, 1)
    if gs is None:
        raise HTTPException(
            status_code=422,
            detail="No LLM provider is configured yet. Open Settings → LLM Providers first.",
        )

    credentials = {
        "anthropic":  not gs.anthropic_api_key_enc,
        "openai":     not gs.openai_api_key_enc,
        "openrouter": not gs.openrouter_api_key_enc,
        "mistral":    not gs.mistral_api_key_enc,
        "groq":       not gs.groq_api_key_enc,
        "xai":        not gs.xai_api_key_enc,
        "deepseek":   not gs.deepseek_api_key_enc,
        "kimi":       not gs.kimi_api_key_enc,
        "zai":        not gs.zai_api_key_enc,
        # A local Ollama server needs no credentials; the hosted service does.
        "ollama":     (gs.ollama_mode or "local") == "cloud" and not gs.ollama_api_key_enc,
    }

    # Reject any provider the engine cannot actually route (a typo or an orphaned
    # value). Without this, an unknown provider passed the guard (dict.get default
    # False = "configured") and then silently fell through to ClaudeEngine at run
    # time — running on whatever Anthropic key happened to be around.
    if provider not in credentials:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown LLM provider '{provider}'. Choose one of: "
                   f"{', '.join(sorted(credentials))}.",
        )

    if credentials[provider]:
        label = {
            "anthropic": "Anthropic", "openai": "OpenAI",
            "openrouter": "OpenRouter", "ollama": "Ollama Cloud",
            "mistral": "Mistral", "groq": "Groq", "xai": "xAI (Grok)",
            "deepseek": "DeepSeek", "kimi": "Kimi (Moonshot)", "zai": "Z.AI (GLM)",
        }.get(provider, provider)
        raise HTTPException(
            status_code=422,
            detail=f"{label} has no API key configured. Add one in Settings → LLM Providers, "
                   f"or pick a provider that is already set up.",
        )


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    # Source Code Review: a repo URL replaces the live web target. Validate it as a
    # public GitHub/GitLab URL and use it as target_url (for display); the live-target
    # DNS/private-IP check is skipped since we never crawl it.
    is_source_review = bool(body.source_repo_url and body.source_repo_url.strip())
    clean_repo: str | None = None
    if is_source_review:
        clean_repo = _validate_repo_url(body.source_repo_url)
        target_url = (body.target_url or "").strip() or clean_repo
    else:
        _validate_target_url(body.target_url)
        target_url = body.target_url
    await _validate_provider_configured(db, body.llm_provider)
    scan = Scan(
        created_by=current_user.id,
        target_url=target_url,
        source_repo_url=clean_repo,
        scan_mode=body.scan_mode,
        llm_provider=body.llm_provider,
        llm_model=body.llm_model,
        project_id=body.project_id,
        scope_include=json.dumps(body.scope_include),
        scope_exclude=json.dumps(body.scope_exclude),
        headers=json.dumps(body.headers),
        cookies=json.dumps(body.cookies),
        max_hypotheses=body.max_hypotheses,
        max_parallel=body.max_parallel,
        feedback_iter=body.feedback_iter,
        exploit_hypo_timeout=body.exploit_hypo_timeout,
        exploit_max_turns=body.exploit_max_turns,
        exploit_hypo_cap=body.exploit_hypo_cap,
        repo_path=body.repo_path,
        custom_prompt=body.custom_prompt,
        target_description=body.target_description,
        status="queued",
    )
    db.add(scan)
    await db.flush()
    scan_id = scan.id

    from backend.models.ops import EngagementBudget
    db.add(EngagementBudget(
        scan_id=scan_id,
        token_budget=max(1000, body.token_budget),
        turn_budget=max(1, body.turn_budget),
        hitl_required=body.hitl_required,
        scope_deny=json.dumps(body.scope_deny or []),
    ))
    await db.commit()

    # Launch background task
    from backend.services.scan_runner import run_scan
    # Create cancel flag before starting task
    get_cancel_flag(scan_id)
    task = asyncio.create_task(run_scan(scan_id), name=f"scan-{scan_id}")
    _active_tasks[scan_id] = task
    task.add_done_callback(lambda _: _active_tasks.pop(scan_id, None))
    task.add_done_callback(lambda _: _cancel_flags.pop(scan_id, None))

    # Re-fetch for response
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    return ScanOut.model_validate(result.scalar_one())


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanOut.model_validate(scan)


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail="Scan is not active")
    if scan.created_by != current_user.id and current_user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Not authorised to cancel this scan")

    # 1. Set cancel flag — scan_runner checks this at each phase boundary
    flag = get_cancel_flag(scan_id)
    flag.set()

    # 2. Cancel asyncio task (injects CancelledError at next await)
    task = _active_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()

    # 3. Immediately mark DB as cancelled so UI reflects it right away
    scan.status = "cancelled"
    scan.completed_at = datetime.now(timezone.utc)
    scan.phase = "cancelled"
    await db.commit()

    return Response(status_code=204)


@router.post("/{scan_id}/rerun", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def rerun_scan(
    scan_id: str,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    original = await db.get(Scan, scan_id)
    if not original:
        raise HTTPException(status_code=404, detail="Scan not found")
    new_scan = Scan(
        created_by=current_user.id,
        target_url=original.target_url,
        scan_mode=original.scan_mode,
        llm_provider=original.llm_provider,
        llm_model=original.llm_model,
        project_id=original.project_id,
        scope_include=original.scope_include,
        scope_exclude=original.scope_exclude,
        headers=original.headers,
        cookies=original.cookies,
        max_hypotheses=original.max_hypotheses,
        max_parallel=original.max_parallel,
        feedback_iter=original.feedback_iter,
        exploit_hypo_timeout=original.exploit_hypo_timeout,
        exploit_max_turns=original.exploit_max_turns,
        exploit_hypo_cap=original.exploit_hypo_cap,
        repo_path=original.repo_path,
        # Preserve the scan TYPE on rerun — without this a Source Code Review would
        # silently rerun as a live web pentest against the repo URL.
        source_repo_url=original.source_repo_url,
        custom_prompt=original.custom_prompt,
        target_description=original.target_description,
        status="queued",
    )
    db.add(new_scan)
    await db.flush()
    new_id = new_scan.id
    await db.commit()

    from backend.services.scan_runner import run_scan
    task = asyncio.create_task(run_scan(new_id), name=f"scan-{new_id}")
    _active_tasks[new_id] = task
    task.add_done_callback(lambda _: _active_tasks.pop(new_id, None))
    task.add_done_callback(lambda _: _cancel_flags.pop(new_id, None))

    result = await db.execute(select(Scan).where(Scan.id == new_id))
    return ScanOut.model_validate(result.scalar_one())


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Cancel if running
    task = _active_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
    await db.delete(scan)
    await db.flush()
    return Response(status_code=204)


@router.get("/{scan_id}/logs", response_model=list[ScanLogOut])
async def get_scan_logs(
    scan_id: str,
    limit: int = Query(500, le=2000),
    offset: int = Query(0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ScanLogOut]:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await db.execute(
        select(ScanLog)
        .where(ScanLog.scan_id == scan_id)
        .order_by(ScanLog.id)
        .limit(limit)
        .offset(offset)
    )
    return [ScanLogOut.model_validate(log) for log in result.scalars().all()]


@router.get("/{scan_id}/lineage")
async def get_scan_lineage(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Exploration lineage: goal → phases → findings (ARTEX-style audit trail)."""
    from backend.models.finding import Finding

    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    logs = (
        await db.execute(
            select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.id).limit(300)
        )
    ).scalars().all()
    findings = (
        await db.execute(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at))
    ).scalars().all()

    nodes: list[dict] = [
        {"id": "goal", "kind": "goal", "label": f"Engage {scan.target_url}", "detail": scan.custom_prompt or scan.target_description},
    ]
    edges: list[dict] = []
    phases_seen: list[str] = []
    for log in logs:
        ph = (log.phase or "").strip() or "ops"
        if ph not in phases_seen:
            phases_seen.append(ph)
            pid = f"phase:{ph}"
            nodes.append({"id": pid, "kind": "intent", "label": ph, "detail": log.message[:240]})
            edges.append({"source": "goal" if len(phases_seen) == 1 else f"phase:{phases_seen[-2]}", "target": pid, "kind": "spawns"})

    last_phase = f"phase:{phases_seen[-1]}" if phases_seen else "goal"
    for f in findings[:40]:
        fid = f"finding:{f.id}"
        nodes.append({
            "id": fid,
            "kind": "finding",
            "label": f.title,
            "detail": f.severity,
            "finding_id": f.id,
        })
        edges.append({"source": last_phase, "target": fid, "kind": "proves"})

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "phase": scan.phase,
        "nodes": nodes,
        "edges": edges,
    }
