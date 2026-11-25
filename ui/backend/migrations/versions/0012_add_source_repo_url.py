"""Add source_repo_url for Source Code Review scans

Revision ID: 0012
Revises: 0011
Create Date: 2026-08-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


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
    if _table_exists(conn, "scans") and not _column_exists(conn, "scans", "source_repo_url"):
        op.add_column("scans", sa.Column("source_repo_url", sa.String(2048), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if _table_exists(conn, "scans") and _column_exists(conn, "scans", "source_repo_url"):
        op.drop_column("scans", "source_repo_url")
