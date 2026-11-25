"""Add Z.AI (GLM) OpenAI-compatible provider columns

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-25
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("zai_api_key_enc", sa.Text(), None),
    ("zai_base_url", sa.String(512), "https://api.z.ai/api/paas/v4"),
    ("zai_max_tokens", sa.Integer(), "4096"),
    ("zai_default_model", sa.String(256), None),
    ("zai_temperature", sa.Float(), "0.7"),
    ("zai_top_p", sa.Float(), None),
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
                sa.Column(
                    name,
                    type_,
                    nullable=True,
                    server_default=default if default is not None else None,
                ),
            )


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "global_settings"):
        return
    for name, _, _ in reversed(_COLUMNS):
        if _column_exists(conn, "global_settings", name):
            op.drop_column("global_settings", name)
