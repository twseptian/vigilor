"""routers/evidence.py — Serve captured evidence files (screenshots, etc.)."""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse

from backend.dependencies import get_current_user
from backend.models.user import User

router = APIRouter(prefix="/evidence", tags=["evidence"])

# Base directory where all scan evidence is stored.
# Must match _DATA_BASE in services/scan_runner.py.
_DATA_BASE = os.environ.get("DATA_BASE", "/app/data")


@router.get("/{path:path}")
async def get_evidence_file(
    path: str,
    current_user: User = Depends(get_current_user),
) -> FileResponse:
    """
    Serve an evidence file (screenshot) by its relative path under DATA_BASE.
    Path is relative to /app/data, e.g. 'scans/{scan_id}/evidence/vuln_proof_0_123.png'.
    Path traversal is rejected (any component containing '..' is blocked).
    """
    # Security: reject any path component containing '..'
    if ".." in path.replace("\\", "/").split("/"):
        raise HTTPException(status_code=403, detail="Path traversal not allowed")

    abs_path = os.path.realpath(os.path.join(_DATA_BASE, path))
    data_base_real = os.path.realpath(_DATA_BASE)

    # Ensure the resolved path is still inside _DATA_BASE
    if not abs_path.startswith(data_base_real + os.sep) and abs_path != data_base_real:
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.isfile(abs_path):
        raise HTTPException(status_code=404, detail="Evidence file not found")

    return FileResponse(abs_path)
