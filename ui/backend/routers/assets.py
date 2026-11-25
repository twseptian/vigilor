"""routers/assets.py — Coverage ledger derived from engagements."""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.scan import Scan
from backend.models.user import User

router = APIRouter(prefix="/assets", tags=["assets"])


def _host(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else f"https://{url}")
        return (p.hostname or url).lower()
    except Exception:
        return url.lower()


class AssetRow(BaseModel):
    host: str
    target_url: str
    scan_count: int
    last_scan_id: str | None
    last_status: str | None
    last_seen: datetime | None
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    findings_info: int
    tested: bool


class AssetsResponse(BaseModel):
    total: int
    tested: int
    assets: list[AssetRow]


class AssetsSummary(BaseModel):
    total: int
    tested: int


@router.get("", response_model=AssetsResponse)
async def list_assets(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AssetsResponse:
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    scans = list(result.scalars().all())

    by_host: dict[str, AssetRow] = {}
    for scan in scans:
        host = _host(scan.target_url or "")
        if not host:
            continue
        existing = by_host.get(host)
        tested = scan.status in ("completed", "running", "failed")
        if existing is None:
            by_host[host] = AssetRow(
                host=host,
                target_url=scan.target_url,
                scan_count=1,
                last_scan_id=scan.id,
                last_status=scan.status,
                last_seen=scan.completed_at or scan.started_at or scan.created_at,
                findings_critical=scan.findings_critical or 0,
                findings_high=scan.findings_high or 0,
                findings_medium=scan.findings_medium or 0,
                findings_low=scan.findings_low or 0,
                findings_info=scan.findings_info or 0,
                tested=tested,
            )
        else:
            existing.scan_count += 1
            existing.findings_critical += scan.findings_critical or 0
            existing.findings_high += scan.findings_high or 0
            existing.findings_medium += scan.findings_medium or 0
            existing.findings_low += scan.findings_low or 0
            existing.findings_info += scan.findings_info or 0
            existing.tested = existing.tested or tested
            # first row is newest due to order_by desc — keep first as last_*

    assets = sorted(by_host.values(), key=lambda a: a.host)
    tested = sum(1 for a in assets if a.tested)
    return AssetsResponse(total=len(assets), tested=tested, assets=assets)


@router.get("/summary", response_model=AssetsSummary)
async def assets_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AssetsSummary:
    data = await list_assets(current_user=current_user, db=db)
    return AssetsSummary(total=data.total, tested=data.tested)


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str  # root|host|endpoint|finding
    tested: bool = False
    meta: dict = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: str = "contains"


class AssetGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


@router.get("/graph", response_model=AssetGraph)
async def asset_graph(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AssetGraph:
    """Hierarchical coverage graph: root → host → sample endpoints from findings."""
    from backend.models.finding import Finding

    data = await list_assets(current_user=current_user, db=db)
    nodes: list[GraphNode] = [GraphNode(id="root", label="Engagement scope", kind="root", tested=True)]
    edges: list[GraphEdge] = []

    findings = (await db.execute(select(Finding).order_by(Finding.created_at.desc()).limit(200))).scalars().all()
    by_host_locs: dict[str, list] = {}
    for f in findings:
        h = _host(f.location or "")
        if not h:
            continue
        by_host_locs.setdefault(h, []).append(f)

    for a in data.assets:
        hid = f"host:{a.host}"
        nodes.append(GraphNode(
            id=hid,
            label=a.host,
            kind="host",
            tested=a.tested,
            meta={
                "scan_count": a.scan_count,
                "critical": a.findings_critical,
                "high": a.findings_high,
                "url": a.target_url,
                "last_scan_id": a.last_scan_id,
            },
        ))
        edges.append(GraphEdge(source="root", target=hid, kind="contains"))
        for i, f in enumerate(by_host_locs.get(a.host, [])[:5]):
            eid = f"ep:{a.host}:{i}"
            path = f.location or f.title
            if len(path) > 60:
                path = path[:57] + "…"
            nodes.append(GraphNode(
                id=eid,
                label=path,
                kind="endpoint",
                tested=True,
                meta={"finding_id": f.id, "severity": f.severity},
            ))
            edges.append(GraphEdge(source=hid, target=eid, kind="has_finding"))

    return AssetGraph(nodes=nodes, edges=edges)
