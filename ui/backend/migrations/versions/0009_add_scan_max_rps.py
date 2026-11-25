"""Add scan_max_rps (outbound request pacing)

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


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
    if not _column_exists(conn, "global_settings", "scan_max_rps"):
        op.add_column(
            "global_settings",
            sa.Column("scan_max_rps", sa.Float(), nullable=True, server_default="0"),
        )


def downgrade() -> None:
    conn = op.get_bind()
    if _column_exists(conn, "global_settings", "scan_max_rps"):
        op.drop_column("global_settings", "scan_max_rps")
