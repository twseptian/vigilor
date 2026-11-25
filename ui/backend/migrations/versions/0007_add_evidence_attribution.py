"""Add evidence attribution fields to findings (who supplied the HTTP evidence)

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("evidence_source", sa.String(16)),
    ("evidence_added_by", sa.String(64)),
    ("evidence_added_at", sa.DateTime()),
)


def _column_exists(conn, table: str, column: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=:t AND column_name=:c"
        ),
        {"t": table, "c": column},
    ).fetchone() is not None


def _table_exists(conn, name: str) -> bool:
    return conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name=:n"
        ),
        {"n": name},
    ).fetchone() is not None


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "findings"):
        return
    for name, type_ in _COLUMNS:
        if not _column_exists(conn, "findings", name):
            op.add_column("findings", sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "findings"):
        return
    for name, _ in reversed(_COLUMNS):
        if _column_exists(conn, "findings", name):
            op.drop_column("findings", name)
