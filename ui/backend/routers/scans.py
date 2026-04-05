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
    repo_path: str | None = None
    custom_prompt: str | None = None
    target_description: str | None = None


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
    duration_seconds: float | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    error_message: str | None
    custom_prompt: str | None = None
    target_description: str | None = None
    max_hypotheses: int = 8
    max_parallel: int = 3
    feedback_iter: int = 2

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


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    _validate_target_url(body.target_url)
    scan = Scan(
        created_by=current_user.id,
        target_url=body.target_url,
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
        repo_path=body.repo_path,
        custom_prompt=body.custom_prompt,
        target_description=body.target_description,
        status="queued",
    )
    db.add(scan)
    await db.flush()
    scan_id = scan.id
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
        repo_path=original.repo_path,
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
