"""routers/findings.py — Findings CRUD and bulk triage."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Literal
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, case
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sqlalchemy import func

from backend.database import get_db
from backend.dependencies import get_current_user, require_min_role
from backend.models.finding import Finding, FindingComment
from backend.models.scan import Scan
from backend.models.user import User
from backend.services.audit import write_audit_log

router = APIRouter(prefix="/findings", tags=["findings"])


async def _sync_scan_severity_counts(db: AsyncSession, scan_id: str) -> None:
    """Recalculate findings_* counters on the Scan row from live Finding data."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        return
    result = await db.execute(
        select(Finding.severity, func.count().label("cnt"))
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    )
    counts = {row.severity: row.cnt for row in result}
    scan.findings_critical = counts.get("Critical", 0)
    scan.findings_high     = counts.get("High", 0)
    scan.findings_medium   = counts.get("Medium", 0)
    scan.findings_low      = counts.get("Low", 0)
    scan.findings_info     = counts.get("Informational", 0)


# ── Schemas ───────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    scan_id: str
    finding_ref: str | None
    title: str
    vuln_type: str | None
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    cvss4_score: float | None
    cvss4_vector: str | None
    status: str
    location: str | None
    description: str | None
    proof_of_concept: str | None
    implications: str | None
    recommendations: str | None
    owasp_category: str | None
    owasp_name: str | None
    cve: str | None
    references: str | None
    screenshot_before: str | None
    screenshot_after: str | None
    created_at: datetime | None
    # Evidence quality / anti-hallucination fields
    has_poc: bool = False
    confidence_score: int = 0
    source_phase: str | None = None
    source_tool: str | None = None
    raw_request: str | None = None
    raw_response: str | None = None
    verification_status: str = "Unverified"
    evidence_source: str | None = None
    evidence_added_by: str | None = None
    evidence_added_at: datetime | None = None
    # Scan context — lets the Findings UI categorise a finding as Web vs Source
    # Code Review and show the originating URL/repo. Populated from Finding.scan.
    scan_target: str | None = None
    source_repo_url: str | None = None

    model_config = {"from_attributes": True}


def _with_scan_context(out: "FindingOut", scan: Any) -> "FindingOut":
    """Attach the finding's scan target + source_repo_url (if the scan was loaded)."""
    if scan is not None:
        out.scan_target = scan.target_url
        out.source_repo_url = scan.source_repo_url
    return out


class FindingUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    recommendations: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cvss4_vector: str | None = None
    cvss4_score: float | None = None
    verification_status: str | None = None
    # Analyst-supplied HTTP evidence for a finding reproduced by hand. Stamped with
    # evidence_source="manual" so it is never mistaken for agent-captured proof.
    raw_request: str | None = None
    raw_response: str | None = None


class CommentCreate(BaseModel):
    body: str


class CommentOut(BaseModel):
    id: str
    finding_id: str
    author_id: str
    author_name: str
    body: str
    created_at: datetime

    model_config = {"from_attributes": True}


class BulkStatusUpdate(BaseModel):
    ids: list[str]
    status: str


class BulkVerificationUpdate(BaseModel):
    ids: list[str]
    verification_status: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[FindingOut])
async def list_all_findings(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    vuln_type: str | None = Query(None),
    scan_id: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[FindingOut]:
    severity_order = case(
        (Finding.severity == "Critical", 1),
        (Finding.severity == "High", 2),
        (Finding.severity == "Medium", 3),
        (Finding.severity == "Low", 4),
        (Finding.severity == "Informational", 5),
        else_=6,
    )
    q = (select(Finding).options(selectinload(Finding.scan))
         .order_by(severity_order, Finding.finding_ref).limit(limit).offset(offset))
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)
    if vuln_type:
        q = q.where(Finding.vuln_type.ilike(f"%{vuln_type}%"))
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    result = await db.execute(q)
    return [_with_scan_context(FindingOut.model_validate(f), f.scan)
            for f in result.scalars().all()]


@router.get("/export")
async def export_findings(
    format: str = Query("csv", regex="^(csv|json|burp)$"),
    scan_id: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Export findings as CSV, JSON, or Burp Suite XML."""
    severity_order = case(
        (Finding.severity == "Critical", 1),
        (Finding.severity == "High", 2),
        (Finding.severity == "Medium", 3),
        (Finding.severity == "Low", 4),
        (Finding.severity == "Informational", 5),
        else_=6,
    )
    q = select(Finding).order_by(severity_order, Finding.finding_ref)
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)
    result = await db.execute(q)
    findings = result.scalars().all()

    if format == "json":
        data = json.dumps(
            [FindingOut.model_validate(f).model_dump(mode="json") for f in findings],
            indent=2,
        )
        return StreamingResponse(
            iter([data]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=findings.json"},
        )

    if format == "burp":
        now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        lines = [f'<?xml version="1.0" encoding="UTF-8"?>\n<issues burpVersion="2.1" exportTime="{now}">']
        for i, f in enumerate(findings, start=1):
            host = ""
            if f.location:
                from urllib.parse import urlparse
                parsed = urlparse(f.location)
                host = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f.location
            path = f.location or "/"
            lines.append(
                f"  <issue>\n"
                f"    <serialNumber>{i}</serialNumber>\n"
                f"    <type>0</type>\n"
                f"    <name>{xml_escape(f.title or '')}</name>\n"
                f"    <host>{xml_escape(host)}</host>\n"
                f"    <path>{xml_escape(path)}</path>\n"
                f"    <severity>{xml_escape(f.severity or '')}</severity>\n"
                f"    <confidence>Certain</confidence>\n"
                f"    <issueBackground>{xml_escape(f.description or '')}</issueBackground>\n"
                f"    <issueDetail>{xml_escape(f.proof_of_concept or '')}</issueDetail>\n"
                f"    <remediationBackground>{xml_escape(f.recommendations or '')}</remediationBackground>\n"
                f"  </issue>"
            )
        lines.append("</issues>")
        xml_body = "\n".join(lines)
        return StreamingResponse(
            iter([xml_body]),
            media_type="application/xml",
            headers={"Content-Disposition": "attachment; filename=findings.xml"},
        )

    # Default: CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Ref", "Title", "Severity", "CVSS", "Status", "Location",
        "OWASP", "CVE", "Description", "Recommendations",
    ])
    for f in findings:
        writer.writerow([
            f.finding_ref or "",
            f.title or "",
            f.severity or "",
            f.cvss_score or "",
            f.status or "",
            f.location or "",
            f"{f.owasp_category or ''} {f.owasp_name or ''}".strip(),
            f.cve or "",
            (f.description or "").replace("\n", " "),
            (f.recommendations or "").replace("\n", " "),
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingOut:
    f = await db.get(Finding, finding_id, options=[selectinload(Finding.scan)])
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _with_scan_context(FindingOut.model_validate(f), f.scan)


@router.patch("/{finding_id}", response_model=FindingOut)
async def update_finding(
    finding_id: str,
    body: FindingUpdate,
    request: Request,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> FindingOut:
    from backend.dependencies import ROLE_HIERARCHY
    f = await db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Approval guard: only reviewer+ can mark as Resolved
    if body.status == "Resolved" and ROLE_HIERARCHY.get(current_user.role, 0) < ROLE_HIERARCHY["reviewer"]:
        raise HTTPException(status_code=403, detail="Only a reviewer or above can mark a finding as Resolved")

    # Audit every triage-relevant field. verification_status and the evidence
    # fields were previously invisible to the audit log even though the bulk
    # endpoints recorded them — an analyst could flip a finding to "False
    # Positive" or attach evidence with no trace.
    _AUDITED = ("status", "severity", "title", "verification_status",
                "evidence_source", "evidence_added_by")
    # Keep None values: attaching evidence for the first time is a None → "manual"
    # transition, and filtering None out would hide exactly that event.
    old_snapshot = {k: getattr(f, k) for k in _AUDITED}

    if body.status is not None:
        f.status = body.status
    if body.severity is not None:
        f.severity = body.severity
    if body.title is not None:
        f.title = body.title
    if body.description is not None:
        f.description = body.description
    if body.recommendations is not None:
        f.recommendations = body.recommendations
    if body.cvss_vector is not None:
        f.cvss_vector = body.cvss_vector
    if body.cvss_score is not None:
        f.cvss_score = body.cvss_score
    if body.cvss4_vector is not None:
        f.cvss4_vector = body.cvss4_vector
    if body.cvss4_score is not None:
        f.cvss4_score = body.cvss4_score
    if body.verification_status is not None:
        f.verification_status = body.verification_status

    # Analyst-supplied evidence. An empty string clears the field; when the finding
    # ends up with any evidence at all we stamp who supplied it, so the UI can keep
    # agent-captured proof visually distinct from hand-pasted proof.
    # confidence_score is deliberately NOT touched here — it is the automatic
    # anti-hallucination signal and must stay a function of what the agent produced.
    if body.raw_request is not None or body.raw_response is not None:
        if body.raw_request is not None:
            f.raw_request = body.raw_request.strip() or None
        if body.raw_response is not None:
            f.raw_response = body.raw_response.strip() or None

        if f.raw_request or f.raw_response:
            f.evidence_source = "manual"
            f.evidence_added_by = current_user.username
            f.evidence_added_at = datetime.utcnow()
        else:
            f.evidence_source = None
            f.evidence_added_by = None
            f.evidence_added_at = None

    await db.flush()

    # Sync scan severity counters whenever severity changes
    await _sync_scan_severity_counts(db, f.scan_id)
    await db.flush()

    new_snapshot = {k: getattr(f, k) for k in old_snapshot}
    changed = {k: v for k, v in new_snapshot.items() if v != old_snapshot.get(k)}
    if changed:
        await write_audit_log(
            db, actor=current_user, action="finding.update",
            resource_type="finding", resource_id=finding_id,
            old_value={k: old_snapshot[k] for k in changed},
            new_value=changed, request=request,
        )
    return _with_scan_context(FindingOut.model_validate(f),
                              await db.get(Scan, f.scan_id))


@router.post("/bulk-status")
async def bulk_update_status(
    body: BulkStatusUpdate,
    request: Request,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    from backend.dependencies import ROLE_HIERARCHY
    if body.status == "Resolved" and ROLE_HIERARCHY.get(current_user.role, 0) < ROLE_HIERARCHY["reviewer"]:
        raise HTTPException(status_code=403, detail="Only a reviewer or above can mark findings as Resolved")
    result = await db.execute(select(Finding).where(Finding.id.in_(body.ids)))
    affected_scan_ids: set[str] = set()
    for f in result.scalars().all():
        old_status = f.status
        f.status = body.status
        affected_scan_ids.add(f.scan_id)
        await write_audit_log(
            db, actor=current_user, action="finding.bulk_status",
            resource_type="finding", resource_id=f.id,
            old_value={"status": old_status}, new_value={"status": body.status},
            request=request,
        )
    await db.flush()
    for scan_id in affected_scan_ids:
        await _sync_scan_severity_counts(db, scan_id)
    await db.flush()
    return Response(status_code=204)


@router.post("/bulk-verification")
async def bulk_update_verification(
    body: BulkVerificationUpdate,
    request: Request,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Triage many findings at once — sweeping a batch of false positives is the
    single most common bulk action on a large scan."""
    allowed = {"Unverified", "Verified", "False Positive"}
    if body.verification_status not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"verification_status must be one of {sorted(allowed)}",
        )

    result = await db.execute(select(Finding).where(Finding.id.in_(body.ids)))
    for f in result.scalars().all():
        old = f.verification_status
        if old == body.verification_status:
            continue
        f.verification_status = body.verification_status
        await write_audit_log(
            db, actor=current_user, action="finding.bulk_verification",
            resource_type="finding", resource_id=f.id,
            old_value={"verification_status": old},
            new_value={"verification_status": body.verification_status},
            request=request,
        )
    await db.flush()
    return Response(status_code=204)


@router.get("/{finding_id}/comments", response_model=list[CommentOut])
async def list_comments(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[CommentOut]:
    f = await db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    result = await db.execute(
        select(FindingComment).where(FindingComment.finding_id == finding_id)
        .order_by(FindingComment.created_at)
    )
    return [CommentOut.model_validate(c) for c in result.scalars().all()]


class RetestOut(BaseModel):
    scan_id: str
    finding_id: str
    message: str


@router.post("/{finding_id}/retest", response_model=RetestOut, status_code=status.HTTP_201_CREATED)
async def retest_finding(
    finding_id: str,
    request: Request,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> RetestOut:
    """Spawn a focused engagement that re-validates a single finding (VIGILOR retest loop)."""
    import asyncio

    f = await db.get(Finding, finding_id, options=[selectinload(Finding.scan)])
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    original = f.scan
    if not original:
        raise HTTPException(status_code=404, detail="Parent scan not found")

    prompt = (
        "RETEST MODE — focused validation of a previously reported finding.\n"
        f"Finding ID: {f.id}\n"
        f"Title: {f.title}\n"
        f"Severity: {f.severity}\n"
        f"Type: {f.vuln_type or 'unknown'}\n"
        f"Location: {f.location or 'n/a'}\n"
        f"Description: {(f.description or '')[:1200]}\n"
        f"Prior PoC: {(f.proof_of_concept or '')[:1200]}\n\n"
        "Goals:\n"
        "1. Reproduce the issue with fresh evidence (request/response).\n"
        "2. Conclude Still reproducible, Fixed, or Cannot confirm.\n"
        "3. Do not expand into unrelated attack surface unless needed to reach the finding.\n"
    )

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
        max_hypotheses=min(original.max_hypotheses or 8, 4),
        max_parallel=original.max_parallel,
        feedback_iter=original.feedback_iter,
        exploit_hypo_timeout=original.exploit_hypo_timeout,
        exploit_max_turns=original.exploit_max_turns,
        exploit_hypo_cap=original.exploit_hypo_cap,
        repo_path=original.repo_path,
        source_repo_url=original.source_repo_url,
        custom_prompt=prompt,
        target_description=f"Retest of finding {f.finding_ref or f.id[:8]}: {f.title}",
        status="queued",
    )
    db.add(new_scan)
    await db.flush()
    new_id = new_scan.id

    await write_audit_log(
        db, actor=current_user, action="finding.retest",
        resource_type="finding", resource_id=finding_id,
        old_value={"status": f.status, "verification_status": f.verification_status},
        new_value={"retest_scan_id": new_id},
        request=request,
    )
    await db.commit()

    from backend.services.scan_runner import run_scan
    from backend.routers import scans as scans_mod

    task = asyncio.create_task(run_scan(new_id), name=f"retest-{new_id}")
    scans_mod._active_tasks[new_id] = task
    task.add_done_callback(lambda _: scans_mod._active_tasks.pop(new_id, None))
    task.add_done_callback(lambda _: scans_mod._cancel_flags.pop(new_id, None))

    return RetestOut(
        scan_id=new_id,
        finding_id=finding_id,
        message="Retest engagement queued",
    )


@router.post("/{finding_id}/comments", response_model=CommentOut, status_code=status.HTTP_201_CREATED)
async def add_comment(
    finding_id: str,
    body: CommentCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CommentOut:
    f = await db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    comment = FindingComment(
        finding_id=finding_id,
        author_id=current_user.id,
        author_name=current_user.username,
        body=body.body,
    )
    db.add(comment)
    await db.flush()
    return CommentOut.model_validate(comment)


@router.delete("/{finding_id}/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_comment(
    finding_id: str,
    comment_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    comment = await db.get(FindingComment, comment_id)
    if not comment or comment.finding_id != finding_id:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comment.author_id != current_user.id and current_user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Not allowed to delete this comment")
    await db.delete(comment)
    await db.flush()
    return Response(status_code=204)
