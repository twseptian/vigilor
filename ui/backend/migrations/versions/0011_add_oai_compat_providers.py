"""Add OpenAI-compatible providers: Mistral, Groq, xAI, DeepSeek, Kimi

Revision ID: 0011
Revises: 0010
Create Date: 2026-08-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

# Each new provider shares the OpenAIEngine via OPENAI_* env vars, so it only needs
# the standard credential/tuning column set (same shape as openrouter).
_COLUMNS = (
    ("mistral_api_key_enc", sa.Text(), None),
    ("mistral_base_url", sa.String(512), "https://api.mistral.ai/v1"),
    ("mistral_max_tokens", sa.Integer(), "4096"),
    ("mistral_default_model", sa.String(256), None),
    ("mistral_temperature", sa.Float(), "0.7"),
    ("mistral_top_p", sa.Float(), None),
    ("groq_api_key_enc", sa.Text(), None),
    ("groq_base_url", sa.String(512), "https://api.groq.com/openai/v1"),
    ("groq_max_tokens", sa.Integer(), "4096"),
    ("groq_default_model", sa.String(256), None),
    ("groq_temperature", sa.Float(), "0.7"),
    ("groq_top_p", sa.Float(), None),
    ("xai_api_key_enc", sa.Text(), None),
    ("xai_base_url", sa.String(512), "https://api.x.ai/v1"),
    ("xai_max_tokens", sa.Integer(), "4096"),
    ("xai_default_model", sa.String(256), None),
    ("xai_temperature", sa.Float(), "0.7"),
    ("xai_top_p", sa.Float(), None),
    ("deepseek_api_key_enc", sa.Text(), None),
    ("deepseek_base_url", sa.String(512), "https://api.deepseek.com"),
    ("deepseek_max_tokens", sa.Integer(), "4096"),
    ("deepseek_default_model", sa.String(256), None),
    ("deepseek_temperature", sa.Float(), "0.7"),
    ("deepseek_top_p", sa.Float(), None),
    ("kimi_api_key_enc", sa.Text(), None),
    ("kimi_base_url", sa.String(512), "https://api.moonshot.ai/v1"),
    ("kimi_max_tokens", sa.Integer(), "4096"),
    ("kimi_default_model", sa.String(256), None),
    ("kimi_temperature", sa.Float(), "0.7"),
    ("kimi_top_p", sa.Float(), None),
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
