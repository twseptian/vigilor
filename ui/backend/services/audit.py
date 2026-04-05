"""services/audit.py — Helpers to write AuditLog entries."""
from __future__ import annotations

import json
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.settings import AuditLog
from backend.models.user import User


async def write_audit_log(
    db: AsyncSession,
    *,
    actor: User,
    action: str,
    resource_type: str,
    resource_id: str,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    """Insert one AuditLog row. Silently swallows errors so it never breaks callers."""
    try:
        ip = None
        ua = None
        if request is not None:
            ip = request.client.host if request.client else None
            ua = request.headers.get("user-agent")
        log = AuditLog(
            actor_id=actor.id,
            actor_name=actor.username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            old_value=json.dumps(old_value) if old_value is not None else None,
            new_value=json.dumps(new_value) if new_value is not None else None,
            ip_address=ip,
            user_agent=ua,
        )
        db.add(log)
        await db.flush()
    except Exception:
        pass
