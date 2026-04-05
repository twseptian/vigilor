"""routers/reports.py — Report generation and download."""
from __future__ import annotations

import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user, require_min_role
from backend.models.report import Report
from backend.models.scan import Scan
from backend.models.user import User

router = APIRouter(tags=["reports"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class ReportCreate(BaseModel):
    format: str = "docx"


class ReportOut(BaseModel):
    id: str
    scan_id: str
    format: str
    file_size_kb: int | None
    generated_by: str
    generated_at: datetime

    model_config = {"from_attributes": True}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/reports", response_model=list[ReportOut])
async def list_reports(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ReportOut]:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await db.execute(
        select(Report).where(Report.scan_id == scan_id).order_by(Report.generated_at.desc())
    )
    return [ReportOut.model_validate(r) for r in result.scalars().all()]


@router.post(
    "/scans/{scan_id}/reports",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
)
async def generate_report(
    scan_id: str,
    body: ReportCreate,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    from backend.config import get_settings
    settings = get_settings()

    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan has not completed yet")

    # Build output path
    from urllib.parse import urlparse
    parsed = urlparse(scan.target_url)
    host_dir = (parsed.netloc or parsed.path).replace(":", "_").replace("/", "_")
    out_dir = os.path.join(settings.REPORTS_DIR, host_dir)
    os.makedirs(out_dir, exist_ok=True)

    # Delegate to the existing ReportingAgent via a thin bridge
    try:
        if body.format == "pdf":
            file_path = await _generate_pdf(scan, db, out_dir)
        else:
            file_path = await _generate_docx(scan, db, out_dir)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    size_kb = None
    if os.path.exists(file_path):
        size_kb = max(1, os.path.getsize(file_path) // 1024)

    report = Report(
        scan_id=scan_id,
        format=body.format,
        file_path=file_path,
        file_size_kb=size_kb,
        generated_by=current_user.id,
    )
    db.add(report)
    await db.flush()
    return ReportOut.model_validate(report)


@router.delete("/reports/{report_id}", status_code=204, response_class=Response)
async def delete_report(
    report_id: str,
    current_user: User = Depends(require_min_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    # Remove file from disk (non-fatal if missing)
    try:
        if os.path.exists(report.file_path):
            os.remove(report.file_path)
    except Exception:
        pass
    await db.delete(report)
    await db.flush()
    return Response(status_code=204)


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")
    media_type = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if report.format == "docx"
        else "application/pdf"
    )
    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=os.path.basename(report.file_path),
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(report.file_path)}"'},
    )


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_findings_list(scan, db):
    """Return findings as dicts for both DOCX and PDF generators."""
    from sqlalchemy import select as _select
    from backend.models.finding import Finding
    result = await db.execute(_select(Finding).where(Finding.scan_id == scan.id))
    db_findings = result.scalars().all()
    return db_findings


async def _generate_pdf(scan, db, out_dir: str) -> str:
    """Generate a PDF report using reportlab."""
    import asyncio
    from backend.services.pdf_report import generate_pdf

    db_findings = await _get_findings_list(scan, db)
    findings = []
    for f in db_findings:
        findings.append({
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "location": f.location,
            "description": f.description,
            "proof_of_concept": f.proof_of_concept,
            "implications": f.implications,
            "recommendations": f.recommendations,
            "owasp_id": f.owasp_category,
            "owasp_name": f.owasp_name,
            "status": f.status,
            "screenshot_before": f.screenshot_before,
            "screenshot_after": f.screenshot_after,
        })

    # Run blocking IO in executor
    loop = asyncio.get_event_loop()
    file_path = await loop.run_in_executor(
        None, lambda: generate_pdf(scan, findings, out_dir)
    )
    return file_path


# ── Internal: generate DOCX using template-based report service ───────────────

async def _generate_docx(scan: Scan, db: AsyncSession, out_dir: str) -> str:
    """Generate a professional WVAPT .docx report following the example-report.docx format."""
    import asyncio
    from sqlalchemy import select as _select
    from backend.models.finding import Finding
    from backend.services.docx_report import generate_docx_report

    result = await db.execute(
        _select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.finding_ref)
    )
    db_findings = result.scalars().all()

    loop = asyncio.get_event_loop()
    file_path = await loop.run_in_executor(
        None, lambda: generate_docx_report(scan, db_findings, out_dir)
    )
    return file_path
