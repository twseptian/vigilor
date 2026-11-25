"""Add Ollama local/cloud mode + key, and OpenRouter auth method

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

_COLUMNS = (
    # "local" (self-hosted, no auth) or "cloud" (ollama.com, API key required)
    ("ollama_mode", sa.String(16), "local"),
    ("ollama_api_key_enc", sa.Text(), None),
    # "manual" (pasted key) or "oauth" (connected via OpenRouter PKCE)
    ("openrouter_auth_method", sa.String(16), "manual"),
)


def _table_exists(conn, name: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name=:n"
        ),
        {"n": name},
    ).fetchone() is not None


def _column_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "global_settings"):
        return
    for name, type_, default in _COLUMNS:
        if not _column_exists(conn, "global_settings", name):
            op.add_column(
                "global_settings",
                sa.Column(name, type_, nullable=True,
                          server_default=default if default is not None else None),
            )


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "global_settings"):
        return
    for name, _, _ in reversed(_COLUMNS):
        if _column_exists(conn, "global_settings", name):
            op.drop_column("global_settings", name)
