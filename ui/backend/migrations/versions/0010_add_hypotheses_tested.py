"""Add hypotheses_tested for live scan progress

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-29
"""
from __future__ import annotations
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def _col(conn, table, col):
    return conn.execute(sa.text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name=:t AND column_name=:c"),
        {"t": table, "c": col}).fetchone() is not None


def upgrade():
    conn = op.get_bind()
    if not _col(conn, "scans", "hypotheses_tested"):
        op.add_column("scans", sa.Column("hypotheses_tested", sa.Integer(),
                                         nullable=False, server_default="0"))


def downgrade():
    conn = op.get_bind()
    if _col(conn, "scans", "hypotheses_tested"):
        op.drop_column("scans", "hypotheses_tested")
