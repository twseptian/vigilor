"""routers/traffic.py — HTTP traffic inspector + ingest (ARTEX-inspired)."""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.finding import Finding
from backend.models.ops import TrafficExchange
from backend.models.user import User

router = APIRouter(prefix="/traffic", tags=["traffic"])

_REQ_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", re.I)
_STATUS = re.compile(r"^HTTP/\d\.\d\s+(\d{3})", re.I | re.M)
_HOST = re.compile(r"(?im)^Host:\s*(.+)$")


def _parse_exchange(raw_req: str | None, raw_resp: str | None, fallback_url: str | None) -> dict:
    method, url, host = "GET", fallback_url or "", None
    req_headers, req_body = None, None
    status_code, resp_headers, resp_body = None, None, None

    if raw_req:
        lines = raw_req.replace("\r\n", "\n").split("\n")
        m = _REQ_LINE.match(lines[0].strip()) if lines else None
        if m:
            method = m.group(1).upper()
            path = m.group(2)
            hm = _HOST.search(raw_req)
            host = hm.group(1).strip() if hm else None
            if path.startswith("http"):
                url = path
            elif host:
                url = f"https://{host}{path if path.startswith('/') else '/' + path}"
            else:
                url = path
        parts = raw_req.split("\n\n", 1)
        req_headers = parts[0][:8000]
        req_body = (parts[1][:50_000] if len(parts) > 1 else None)

    if raw_resp:
        sm = _STATUS.search(raw_resp)
        if sm:
            status_code = int(sm.group(1))
        parts = raw_resp.split("\n\n", 1)
        resp_headers = parts[0][:8000]
        resp_body = (parts[1][:50_000] if len(parts) > 1 else None)

    if not host and url:
        try:
            host = urlparse(url if "://" in url else f"https://{url}").hostname
        except Exception:
            host = None

    return {
        "method": method,
        "url": url or "(unknown)",
        "host": host,
        "status_code": status_code,
        "request_headers": req_headers,
        "request_body": req_body,
        "response_headers": resp_headers,
        "response_body": resp_body,
    }


class TrafficOut(BaseModel):
    id: str
    scan_id: str | None
    finding_id: str | None
    method: str
    url: str
    host: str | None
    status_code: int | None
    request_headers: str | None = None
    request_body: str | None = None
    response_headers: str | None = None
    response_body: str | None = None
    source: str
    tags: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class TrafficList(BaseModel):
    total: int
    items: list[TrafficOut]


class TrafficIngest(BaseModel):
    method: str = "GET"
    url: str
    status_code: int | None = None
    request_headers: str | None = None
    request_body: str | None = None
    response_headers: str | None = None
    response_body: str | None = None
    scan_id: str | None = None
    finding_id: str | None = None
    source: str = "extension"
    tags: str | None = None


class LinkFindingBody(BaseModel):
    finding_id: str = Field(..., min_length=1)


@router.get("", response_model=TrafficList)
async def list_traffic(
    q: str | None = None,
    host: str | None = None,
    method: str | None = None,
    status_class: str | None = Query(None, description="2xx|3xx|4xx|5xx"),
    scan_id: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TrafficList:
    stmt = select(TrafficExchange)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(TrafficExchange.url.ilike(like), TrafficExchange.host.ilike(like)))
    if host:
        stmt = stmt.where(TrafficExchange.host.ilike(f"%{host}%"))
    if method:
        stmt = stmt.where(TrafficExchange.method == method.upper())
    if scan_id:
        stmt = stmt.where(TrafficExchange.scan_id == scan_id)
    if status_class and status_class[0].isdigit():
        lo = int(status_class[0]) * 100
        stmt = stmt.where(TrafficExchange.status_code >= lo, TrafficExchange.status_code < lo + 100)

    count_q = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_q)).scalar_one()
    rows = (
        await db.execute(stmt.order_by(TrafficExchange.created_at.desc()).offset(offset).limit(limit))
    ).scalars().all()
    return TrafficList(total=total, items=[TrafficOut.model_validate(r) for r in rows])


@router.get("/{traffic_id}", response_model=TrafficOut)
async def get_traffic(
    traffic_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TrafficOut:
    row = (await db.execute(select(TrafficExchange).where(TrafficExchange.id == traffic_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Traffic exchange not found")
    return TrafficOut.model_validate(row)


@router.post("/ingest", response_model=TrafficOut)
async def ingest_traffic(
    body: TrafficIngest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TrafficOut:
    host = None
    try:
        host = urlparse(body.url if "://" in body.url else f"https://{body.url}").hostname
    except Exception:
        pass
    row = TrafficExchange(
        scan_id=body.scan_id,
        finding_id=body.finding_id,
        method=body.method.upper(),
        url=body.url[:4096],
        host=host,
        status_code=body.status_code,
        request_headers=(body.request_headers or "")[:8000] or None,
        request_body=(body.request_body or "")[:50_000] or None,
        response_headers=(body.response_headers or "")[:8000] or None,
        response_body=(body.response_body or "")[:50_000] or None,
        source=body.source[:32],
        tags=body.tags,
    )
    db.add(row)
    await db.flush()
    return TrafficOut.model_validate(row)


@router.post("/sync-from-findings")
async def sync_from_findings(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Populate traffic store from findings that already carry raw request/response."""
    existing = {
        r for r in (
            await db.execute(select(TrafficExchange.finding_id).where(TrafficExchange.finding_id.is_not(None)))
        ).scalars().all()
    }
    findings = (
        await db.execute(
            select(Finding).where(
                or_(Finding.raw_request.is_not(None), Finding.raw_response.is_not(None))
            )
        )
    ).scalars().all()

    created = 0
    for f in findings:
        if f.id in existing:
            continue
        parsed = _parse_exchange(f.raw_request, f.raw_response, f.location)
        db.add(TrafficExchange(
            scan_id=f.scan_id,
            finding_id=f.id,
            source="finding",
            tags=f.severity,
            **parsed,
        ))
        created += 1
    return {"created": created, "skipped": len(existing)}


@router.post("/{traffic_id}/link-finding", response_model=TrafficOut)
async def link_finding(
    traffic_id: str,
    body: LinkFindingBody,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TrafficOut:
    row = (await db.execute(select(TrafficExchange).where(TrafficExchange.id == traffic_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Traffic exchange not found")
    finding = (await db.execute(select(Finding).where(Finding.id == body.finding_id))).scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")
    row.finding_id = finding.id
    row.scan_id = finding.scan_id
    await db.flush()
    return TrafficOut.model_validate(row)
