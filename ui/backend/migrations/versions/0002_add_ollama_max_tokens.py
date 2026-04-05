"""Add ollama_max_tokens to global_settings

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-02
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    # Add column only if it doesn't exist yet (idempotent)
    row = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name='global_settings' AND column_name='ollama_max_tokens'"
        )
    ).fetchone()
    if row is None:
        op.add_column(
            "global_settings",
            sa.Column("ollama_max_tokens", sa.Integer(), nullable=True, server_default="512"),
        )


def downgrade() -> None:
    op.drop_column("global_settings", "ollama_max_tokens")
