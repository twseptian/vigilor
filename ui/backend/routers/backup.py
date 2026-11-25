"""routers/backup.py — Full backup: database + evidence files bundled as ZIP."""
from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import require_min_role
from backend.models.finding import Finding, FindingComment
from backend.models.project import Project
from backend.models.scan import Scan, ScanLog
from backend.models.user import User

router = APIRouter(prefix="/admin/backup", tags=["backup"])

_DT_FMT = "%Y-%m-%dT%H:%M:%S.%f"

# Where scan evidence (screenshots) are stored inside the container
_SCANS_BASE = os.environ.get("SCANS_DATA_PATH", "/app/data/scans")


def _dt(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.strftime(_DT_FMT)
    return str(v)


def _scan_dict(s: Scan) -> dict:
    return {
        "id": s.id, "project_id": s.project_id, "created_by": s.created_by,
        "target_url": s.target_url, "scan_mode": s.scan_mode,
        "llm_provider": s.llm_provider, "llm_model": s.llm_model,
        "status": s.status, "phase": s.phase, "phase_detail": s.phase_detail,
        "scope_include": s.scope_include, "scope_exclude": s.scope_exclude,
        "headers": s.headers, "cookies": s.cookies,
        "max_hypotheses": s.max_hypotheses, "max_parallel": s.max_parallel,
        "feedback_iter": s.feedback_iter, "repo_path": s.repo_path,
        "custom_prompt": s.custom_prompt, "target_description": s.target_description,
        "findings_critical": s.findings_critical, "findings_high": s.findings_high,
        "findings_medium": s.findings_medium, "findings_low": s.findings_low,
        "findings_info": s.findings_info, "hypotheses_total": s.hypotheses_total,
        "hypotheses_confirmed": s.hypotheses_confirmed,
        "duration_seconds": s.duration_seconds,
        "error_message": s.error_message,
        "started_at": _dt(s.started_at), "completed_at": _dt(s.completed_at),
        "created_at": _dt(s.created_at),
    }


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id, "scan_id": f.scan_id, "finding_ref": f.finding_ref,
        "title": f.title, "vuln_type": f.vuln_type, "severity": f.severity,
        "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
        "cvss4_score": f.cvss4_score, "cvss4_vector": f.cvss4_vector,
        "status": f.status, "location": f.location,
        "description": f.description, "proof_of_concept": f.proof_of_concept,
        "implications": f.implications, "recommendations": f.recommendations,
        "owasp_category": f.owasp_category, "owasp_name": f.owasp_name,
        "cve": f.cve, "references": f.references,
        "screenshot_before": f.screenshot_before,
        "screenshot_after": f.screenshot_after,
        "created_at": _dt(f.created_at),
    }


def _comment_dict(c: FindingComment) -> dict:
    return {
        "id": c.id, "finding_id": c.finding_id,
        "author_id": c.author_id, "author_name": c.author_name,
        "body": c.body, "created_at": _dt(c.created_at),
    }


def _project_dict(p: Project) -> dict:
    return {
        "id": p.id, "name": p.name, "description": p.description,
        "owner_id": p.owner_id,
        "created_at": _dt(p.created_at), "updated_at": _dt(p.updated_at),
        "archived_at": _dt(p.archived_at),
    }


# ── Export ────────────────────────────────────────────────────────────────────

@router.get("/export")
async def export_backup(
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Export full backup as ZIP: database.json + all evidence screenshots."""
    projects = (await db.execute(select(Project))).scalars().all()
    scans    = (await db.execute(select(Scan).order_by(Scan.created_at))).scalars().all()
    findings = (await db.execute(select(Finding).order_by(Finding.created_at))).scalars().all()
    comments = (await db.execute(select(FindingComment).order_by(FindingComment.created_at))).scalars().all()

    scan_ids = {s.id for s in scans}

    payload = {
        "version": "2.0",
        "exported_at": datetime.utcnow().strftime(_DT_FMT),
        "exported_by": current_user.username,
        "stats": {
            "projects": len(projects),
            "scans": len(scans),
            "findings": len(findings),
            "comments": len(comments),
        },
        "projects":         [_project_dict(p) for p in projects],
        "scans":            [_scan_dict(s)    for s in scans],
        "findings":         [_finding_dict(f) for f in findings],
        "finding_comments": [_comment_dict(c) for c in comments],
    }

    db_json = json.dumps(payload, indent=2, ensure_ascii=False).encode()

    # Build ZIP in memory
    buf = io.BytesIO()
    evidence_count = 0
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1. Database JSON
        zf.writestr("database.json", db_json)

        # 2. Evidence files for each scan
        scans_base = Path(_SCANS_BASE)
        for scan_id in scan_ids:
            scan_dir = scans_base / scan_id
            if not scan_dir.exists():
                continue
            for fpath in scan_dir.rglob("*"):
                if fpath.is_file():
                    # Store as evidence/<scan_id>/evidence/filename.png
                    arcname = f"evidence/{scan_id}/{fpath.relative_to(scan_dir)}"
                    try:
                        zf.write(str(fpath), arcname)
                        evidence_count += 1
                    except Exception:
                        pass  # skip unreadable files

    buf.seek(0)
    filename = f"pentest_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
    print(f"[Backup] Export: {len(scans)} scan(s), {len(findings)} finding(s), {evidence_count} evidence file(s) → {filename}")

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Import ────────────────────────────────────────────────────────────────────

@router.post("/import")
async def import_backup(
    file: UploadFile = File(...),
    current_user: User = Depends(require_min_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Import a ZIP backup. Restores database records AND evidence files.
    Accepts both v2.0 ZIP and legacy v1.0 JSON for backwards compatibility.
    Existing records (by ID) are skipped — no data is overwritten.
    """
    fname = file.filename or ""
    raw = await file.read()

    # ── Detect format ─────────────────────────────────────────────────────────
    if fname.endswith(".zip"):
        payload, evidence_map = _parse_zip(raw)
    elif fname.endswith(".json"):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
        evidence_map = {}
    else:
        raise HTTPException(status_code=400, detail="Only .zip or .json backup files are accepted")

    version = payload.get("version", "1.0")
    if version not in ("1.0", "2.0"):
        raise HTTPException(status_code=400, detail=f"Unsupported backup version: {version}")

    inserted = {"projects": 0, "scans": 0, "findings": 0, "comments": 0}

    # ── Projects ──────────────────────────────────────────────────────────────
    for p in payload.get("projects", []):
        if not await db.get(Project, p["id"]):
            db.add(Project(
                id=p["id"], name=p["name"], description=p.get("description"),
                owner_id=current_user.id,
                created_at=_parse_dt(p.get("created_at")),
                updated_at=_parse_dt(p.get("updated_at")),
                archived_at=_parse_dt(p.get("archived_at")),
            ))
            inserted["projects"] += 1
    await db.flush()

    # ── Scans ─────────────────────────────────────────────────────────────────
    for s in payload.get("scans", []):
        if not await db.get(Scan, s["id"]):
            db.add(Scan(
                id=s["id"], project_id=s.get("project_id"),
                created_by=current_user.id,
                target_url=s["target_url"], scan_mode=s.get("scan_mode", "full"),
                llm_provider=s.get("llm_provider", "openai"), llm_model=s.get("llm_model"),
                status=s.get("status", "completed"),
                phase=s.get("phase"), phase_detail=s.get("phase_detail"),
                scope_include=s.get("scope_include"), scope_exclude=s.get("scope_exclude"),
                headers=s.get("headers"), cookies=s.get("cookies"),
                max_hypotheses=s.get("max_hypotheses", 8),
                max_parallel=s.get("max_parallel", 3),
                feedback_iter=s.get("feedback_iter", 2),
                repo_path=s.get("repo_path"), custom_prompt=s.get("custom_prompt"),
                target_description=s.get("target_description"),
                findings_critical=s.get("findings_critical", 0),
                findings_high=s.get("findings_high", 0),
                findings_medium=s.get("findings_medium", 0),
                findings_low=s.get("findings_low", 0),
                findings_info=s.get("findings_info", 0),
                hypotheses_total=s.get("hypotheses_total", 0),
                hypotheses_confirmed=s.get("hypotheses_confirmed", 0),
                duration_seconds=s.get("duration_seconds"),
                error_message=s.get("error_message"),
                started_at=_parse_dt(s.get("started_at")),
                completed_at=_parse_dt(s.get("completed_at")),
                created_at=_parse_dt(s.get("created_at")),
            ))
            inserted["scans"] += 1
    await db.flush()

    # ── Findings ──────────────────────────────────────────────────────────────
    for f in payload.get("findings", []):
        if not await db.get(Finding, f["id"]):
            db.add(Finding(
                id=f["id"], scan_id=f["scan_id"], finding_ref=f.get("finding_ref"),
                title=f["title"], vuln_type=f.get("vuln_type"), severity=f.get("severity", "Medium"),
                cvss_score=f.get("cvss_score"), cvss_vector=f.get("cvss_vector"),
                cvss4_score=f.get("cvss4_score"), cvss4_vector=f.get("cvss4_vector"),
                status=f.get("status", "Open"), location=f.get("location"),
                description=f.get("description"), proof_of_concept=f.get("proof_of_concept"),
                implications=f.get("implications"), recommendations=f.get("recommendations"),
                owasp_category=f.get("owasp_category"), owasp_name=f.get("owasp_name"),
                cve=f.get("cve"), references=f.get("references"),
                screenshot_before=f.get("screenshot_before"),
                screenshot_after=f.get("screenshot_after"),
                created_at=_parse_dt(f.get("created_at")),
            ))
            inserted["findings"] += 1
    await db.flush()

    # ── Comments ──────────────────────────────────────────────────────────────
    for c in payload.get("finding_comments", []):
        if not await db.get(FindingComment, c["id"]):
            db.add(FindingComment(
                id=c["id"], finding_id=c["finding_id"],
                author_id=current_user.id, author_name=c.get("author_name", current_user.username),
                body=c["body"], created_at=_parse_dt(c.get("created_at")),
            ))
            inserted["comments"] += 1
    await db.flush()

    # ── Evidence files ────────────────────────────────────────────────────────
    evidence_restored = 0
    if evidence_map:
        scans_base = Path(_SCANS_BASE)
        for arcname, file_bytes in evidence_map.items():
            # arcname format: evidence/<scan_id>/evidence/filename.png
            parts = Path(arcname).parts
            if len(parts) < 3:
                continue
            # Reconstruct path: /app/data/scans/<scan_id>/evidence/filename.png
            rel = Path(*parts[1:])  # strip leading "evidence/"
            dest = scans_base / rel
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    dest.write_bytes(file_bytes)
                    evidence_restored += 1
            except Exception as e:
                print(f"[Backup/Import] Could not restore {dest}: {e}")

    print(
        f"[Backup] Import: {inserted['scans']} scan(s), {inserted['findings']} finding(s), "
        f"{inserted['projects']} project(s), {evidence_restored} evidence file(s) restored"
    )

    return {
        "status": "ok",
        "inserted": inserted,
        "evidence_restored": evidence_restored,
        "message": (
            f"Imported {inserted['scans']} scan(s), {inserted['findings']} finding(s), "
            f"{inserted['projects']} project(s), {inserted['comments']} comment(s) — "
            f"{evidence_restored} evidence file(s) restored."
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_zip(raw: bytes) -> tuple[dict, dict[str, bytes]]:
    """Extract database.json and evidence files from a v2.0 ZIP backup."""
    evidence_map: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            if "database.json" not in names:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid ZIP backup: missing database.json"
                )
            payload = json.loads(zf.read("database.json"))
            for name in names:
                if name.startswith("evidence/") and not name.endswith("/"):
                    evidence_map[name] = zf.read(name)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid database.json in ZIP: {e}")
    return payload, evidence_map


def _parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.strptime(v, _DT_FMT)
    except ValueError:
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
