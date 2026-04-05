"""
config.py — Application settings loaded from environment variables.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── App ──────────────────────────────────────────────────────────────
    APP_NAME: str = "Pentest AI Agent"
    APP_VERSION: str = "0.5.0"
    DEBUG: bool = False
    FRONTEND_URL: str = "http://localhost:5173"

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./pentest_ui.db"

    # ── Auth ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = "changeme-generate-with-openssl-rand-hex-32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Encryption (for API keys stored in DB) ───────────────────────────
    ENCRYPTION_KEY: str = "changeme-32-byte-key-base64-encoded"

    # ── First-run admin account ──────────────────────────────────────────
    FIRST_ADMIN_USERNAME: str = "admin"
    FIRST_ADMIN_PASSWORD: str = "changeme123"
    FIRST_ADMIN_EMAIL: str = "admin@localhost"

    # ── Scan limits ──────────────────────────────────────────────────────
    MAX_CONCURRENT_SCANS: int = 3

    # ── Reports output path ──────────────────────────────────────────────
    REPORTS_DIR: str = "./reports"

    # ── CORS ─────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
