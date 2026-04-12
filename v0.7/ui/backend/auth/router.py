"""auth/router.py — Login, logout, refresh, and /me endpoints."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.user import User
from backend.auth import service as auth_svc
from backend.limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Schemas (inline — small enough not to warrant a separate file) ───────────

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    username: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    last_login_at: datetime | None = None

    model_config = {"from_attributes": True}


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(OAuth2PasswordRequestForm),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    user = await auth_svc.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = auth_svc.create_access_token(user.id, user.role)
    refresh_token = auth_svc.create_refresh_token(user.id)
    await auth_svc.save_refresh_token(
        db, user.id, refresh_token, request.headers.get("user-agent")
    )
    user.last_login_at = datetime.utcnow()
    await db.flush()
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        username=user.username,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    user = await auth_svc.validate_and_rotate_refresh_token(db, body.refresh_token)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    access_token = auth_svc.create_access_token(user.id, user.role)
    new_refresh = auth_svc.create_refresh_token(user.id)
    await auth_svc.save_refresh_token(db, user.id, new_refresh)
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        role=user.role,
        username=user.username,
    )


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    await auth_svc.revoke_all_user_tokens(db, current_user.id)
    return Response(status_code=204)


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(current_user)
