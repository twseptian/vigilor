"""
backend/main.py — FastAPI application entrypoint.

Run with:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.config import get_settings
from backend.limiter import limiter
from backend.database import create_tables
from backend.auth.router import router as auth_router
from backend.routers.scans import router as scans_router
from backend.routers.findings import router as findings_router
from backend.routers.projects import router as projects_router
from backend.routers.settings import router as settings_router
from backend.routers.users import router as users_router
from backend.routers.reports import router as reports_router
from backend.routers.dashboard import router as dashboard_router
from backend.routers.evidence import router as evidence_router
from backend.routers.backup import router as backup_router
from backend.routers.workflows import router as workflows_router
from backend.routers.assets import router as assets_router
from backend.routers.activity import router as activity_router
from backend.routers.traffic import router as traffic_router
from backend.routers.approvals import router as approvals_router
from backend.routers.usage import router as usage_router
from backend.websocket.router import router as ws_router
# Ensure ops models are registered for create_tables()
import backend.models  # noqa: F401

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    # ── Startup ──────────────────────────────────────────────────────────
    await create_tables()
    await _seed_first_admin()

    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(_purge_old_reports, "interval", hours=24, next_run_time=datetime.now(timezone.utc))
    scheduler.start()
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────
    scheduler.shutdown(wait=False)


async def _seed_first_admin() -> None:
    """Create the initial admin user if none exists, or sync credentials from env."""
    from sqlalchemy import select, func
    from backend.database import AsyncSessionLocal
    from backend.models.user import User
    from backend.auth.service import hash_password

    # Skip sync if credentials are still at default placeholder values
    _default_pw = "changeme123"
    _env_pw     = settings.FIRST_ADMIN_PASSWORD
    _env_user   = settings.FIRST_ADMIN_USERNAME

    async with AsyncSessionLocal() as db:
        count_result = await db.execute(select(func.count()).select_from(User))
        if count_result.scalar_one() == 0:
            # Fresh install — create first admin
            admin = User(
                username=_env_user,
                email=settings.FIRST_ADMIN_EMAIL,
                password_hash=hash_password(_env_pw),
                role="superadmin",
            )
            db.add(admin)
            await db.commit()
            print(f"[*] Created first admin: {_env_user}")
        elif _env_pw != _default_pw:
            # Env password was customised — update the admin account to match
            result = await db.execute(
                select(User).where(User.username == _env_user)
            )
            admin = result.scalar_one_or_none()
            if admin:
                admin.password_hash = hash_password(_env_pw)
                await db.commit()
                print(f"[*] Synced admin password from env: {_env_user}")


async def _purge_old_reports() -> None:
    """Delete report files and DB rows older than report_retention_days."""
    from sqlalchemy import select
    from backend.database import AsyncSessionLocal
    from backend.models.report import Report
    from backend.models.settings import GlobalSettings

    async with AsyncSessionLocal() as db:
        gs_result = await db.execute(select(GlobalSettings).where(GlobalSettings.id == 1))
        gs = gs_result.scalar_one_or_none()
        retention_days = gs.report_retention_days if gs else 90

        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        old_reports = await db.execute(select(Report).where(Report.generated_at < cutoff))
        deleted = 0
        for report in old_reports.scalars().all():
            try:
                if os.path.exists(report.file_path):
                    os.remove(report.file_path)
            except OSError:
                pass
            await db.delete(report)
            deleted += 1
        if deleted:
            await db.commit()
            print(f"[retention] Purged {deleted} report(s) older than {retention_days} days")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="VIGILOR Web Dashboard API",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── Rate limiter ──────────────────────────────────────────────────────────────

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# ── API routers ───────────────────────────────────────────────────────────────

API_PREFIX = "/api/v1"

app.include_router(auth_router,       prefix=API_PREFIX)
app.include_router(dashboard_router,  prefix=API_PREFIX)
app.include_router(scans_router,      prefix=API_PREFIX)
app.include_router(findings_router,   prefix=API_PREFIX)
app.include_router(projects_router,   prefix=API_PREFIX)
app.include_router(settings_router,   prefix=API_PREFIX)
app.include_router(users_router,      prefix=API_PREFIX)
app.include_router(reports_router,    prefix=API_PREFIX)
app.include_router(evidence_router,   prefix=API_PREFIX)
app.include_router(backup_router,     prefix=API_PREFIX)
app.include_router(workflows_router,  prefix=API_PREFIX)
app.include_router(assets_router,     prefix=API_PREFIX)
app.include_router(activity_router,   prefix=API_PREFIX)
app.include_router(traffic_router,    prefix=API_PREFIX)
app.include_router(approvals_router,  prefix=API_PREFIX)
app.include_router(usage_router,      prefix=API_PREFIX)

# ── WebSocket ─────────────────────────────────────────────────────────────────

app.include_router(ws_router)

# ── Health check ─────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok", "version": settings.APP_VERSION}
