"""Add reviewer to user_role enum

Revision ID: 0001
Revises:
Create Date: 2026-04-02
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    # Check if the enum type exists.
    # On a fresh install create_tables() creates it with 'reviewer' already present,
    # so this migration only needs to act on existing installations.
    row = conn.execute(
        sa.text("SELECT 1 FROM pg_type WHERE typname = 'user_role'")
    ).fetchone()
    if row is None:
        return  # Fresh install — SQLAlchemy will create the enum correctly via create_tables()

    # ALTER TYPE … ADD VALUE cannot run inside a transaction block in PostgreSQL.
    # We commit the current transaction first, run the DDL, then let Alembic
    # stamp the revision in a new transaction.
    conn.execute(sa.text("COMMIT"))
    conn.execute(sa.text(
        "ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'reviewer' AFTER 'admin'"
    ))


def downgrade() -> None:
    # PostgreSQL does not support removing enum values without recreating the type.
    pass
