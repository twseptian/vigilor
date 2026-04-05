"""routers/projects.py — Project and membership management."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user, require_min_role
from backend.models.project import Project, ProjectMember
from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.models.user import User

router = APIRouter(prefix="/projects", tags=["projects"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    description: str | None = None


class ProjectOut(BaseModel):
    id: str
    name: str
    description: str | None
    owner_id: str
    created_at: datetime
    archived_at: datetime | None

    model_config = {"from_attributes": True}


class ProjectStats(BaseModel):
    scan_count: int
    finding_count: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class MemberAdd(BaseModel):
    user_id: str
    role: str = "viewer"


class MemberOut(BaseModel):
    user_id: str
    username: str
    role: str
    added_at: datetime

    model_config = {"from_attributes": True}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ProjectOut])
async def list_projects(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectOut]:
    # Admin/superadmin see all; others see only projects they're members of
    if current_user.role in ("admin", "superadmin"):
        result = await db.execute(select(Project).where(Project.archived_at == None).order_by(Project.created_at.desc()))
    else:
        result = await db.execute(
            select(Project)
            .join(ProjectMember, Project.id == ProjectMember.project_id)
            .where(ProjectMember.user_id == current_user.id, Project.archived_at == None)
            .order_by(Project.created_at.desc())
        )
    return [ProjectOut.model_validate(p) for p in result.scalars().all()]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectCreate,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    project = Project(name=body.name, description=body.description, owner_id=current_user.id)
    db.add(project)
    await db.flush()
    # Auto-add creator as owner member
    db.add(ProjectMember(project_id=project.id, user_id=current_user.id, role="owner"))
    await db.flush()
    return ProjectOut.model_validate(project)


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectOut.model_validate(p)


@router.get("/{project_id}/stats", response_model=ProjectStats)
async def project_stats(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ProjectStats:
    # Scan count
    scan_count_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.project_id == project_id)
    )
    scan_count = scan_count_result.scalar_one()

    # Findings per severity (join through scan)
    findings_result = await db.execute(
        select(Finding.severity, func.count().label("cnt"))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.project_id == project_id)
        .group_by(Finding.severity)
    )
    sev_counts: dict[str, int] = {}
    total = 0
    for row in findings_result:
        sev_counts[row.severity.lower()] = row.cnt
        total += row.cnt

    return ProjectStats(
        scan_count=scan_count,
        finding_count=total,
        critical=sev_counts.get("critical", 0),
        high=sev_counts.get("high", 0),
        medium=sev_counts.get("medium", 0),
        low=sev_counts.get("low", 0),
        informational=sev_counts.get("informational", 0),
    )


@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(p)
    await db.flush()
    return Response(status_code=204)


@router.get("/{project_id}/members", response_model=list[MemberOut])
async def list_members(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[MemberOut]:
    result = await db.execute(
        select(ProjectMember, User.username)
        .join(User, ProjectMember.user_id == User.id)
        .where(ProjectMember.project_id == project_id)
    )
    out = []
    for member, username in result:
        out.append(MemberOut(
            user_id=member.user_id,
            username=username,
            role=member.role,
            added_at=member.added_at,
        ))
    return out


@router.post("/{project_id}/members")
async def add_member(
    project_id: str,
    body: MemberAdd,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    db.add(ProjectMember(project_id=project_id, user_id=body.user_id, role=body.role))
    await db.flush()
    return Response(status_code=204)


@router.delete("/{project_id}/members/{user_id}")
async def remove_member(
    project_id: str,
    user_id: str,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    result = await db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user_id,
        )
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(member)
    await db.flush()
    return Response(status_code=204)
