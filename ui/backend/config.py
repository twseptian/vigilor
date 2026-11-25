"""
config.py — Application settings loaded from environment variables.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── App ──────────────────────────────────────────────────────────────
    APP_NAME: str = "VIGILOR"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    FRONTEND_URL: str = "http://localhost:5173"

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./pentest_ui.db"

    # ── Auth ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = "changeme-generate-with-openssl-rand-hex-32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480   # 8 hours
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
    # Stored as a plain string to avoid pydantic-settings v2 auto-JSON-parsing
    # on list[str] fields.  Accepts either format at runtime:
    #   '["http://host:3000","http://host"]'   — JSON array
    #   'http://host:3000,http://host'          — comma-separated
    CORS_ORIGINS: str = "http://localhost,http://localhost:80,http://localhost:3000,http://localhost:5173"

    @property
    def cors_origins_list(self) -> list[str]:
        v = self.CORS_ORIGINS.strip()
        if v.startswith("["):
            return json.loads(v)
        return [o.strip() for o in v.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
