"""Add attack_workflows table (attack chain / exploitation workflow graphs)

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision = "0005"
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


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "scans"):
        return
    if _table_exists(conn, "attack_workflows"):
        return

    op.create_table(
        "attack_workflows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False, server_default="scan"),
        sa.Column("generator", sa.String(32), nullable=False, server_default="heuristic"),
        sa.Column("llm_model", sa.String(128), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("graph_json", sa.Text(), nullable=True),
        sa.Column("chains_json", sa.Text(), nullable=True),
        sa.Column("mermaid", sa.Text(), nullable=True),
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("chain_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", "finding_id", name="uq_attack_workflow_scan_finding"),
    )
    op.create_index("ix_attack_workflows_scan_id", "attack_workflows", ["scan_id"])
    op.create_index("ix_attack_workflows_finding_id", "attack_workflows", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_attack_workflows_finding_id", table_name="attack_workflows")
    op.drop_index("ix_attack_workflows_scan_id", table_name="attack_workflows")
    op.drop_table("attack_workflows")
