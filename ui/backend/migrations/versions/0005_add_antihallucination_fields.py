"""Add anti-hallucination / evidence quality fields to findings table

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_NEW_COLS = [
    ("has_poc",             sa.Boolean(),     "false"),
    ("confidence_score",    sa.Integer(),     "0"),
    ("source_phase",        sa.String(32),    None),
    ("source_tool",         sa.String(64),    None),
    ("raw_request",         sa.Text(),        None),
    ("raw_response",        sa.Text(),        None),
    ("verification_status", sa.String(32),    "'Unverified'"),
]


def upgrade() -> None:
    conn = op.get_bind()
    table_exists = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name='findings'"
        )
    ).fetchone()
    if table_exists is None:
        return

    for col_name, col_type, default in _NEW_COLS:
        col_exists = conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns "
                f"WHERE table_name='findings' AND column_name='{col_name}'"
            )
        ).fetchone()
        if col_exists is None:
            op.add_column(
                "findings",
                sa.Column(
                    col_name,
                    col_type,
                    nullable=True,
                    server_default=sa.text(default) if default else None,
                ),
            )


def downgrade() -> None:
    for col_name, _, _ in _NEW_COLS:
        op.drop_column("findings", col_name)
