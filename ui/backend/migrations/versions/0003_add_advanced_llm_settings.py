"""Add per-provider advanced LLM settings (temperature, top_p, penalties)

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-18
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_NEW_COLS = [
    # Anthropic
    ("anthropic_temperature",        sa.Float(),   "0.7"),
    ("anthropic_top_p",              sa.Float(),   None),
    # OpenAI
    ("openai_temperature",           sa.Float(),   "0.7"),
    ("openai_top_p",                 sa.Float(),   None),
    ("openai_frequency_penalty",     sa.Float(),   "0"),
    ("openai_presence_penalty",      sa.Float(),   "0"),
    # OpenRouter
    ("openrouter_temperature",       sa.Float(),   "0.7"),
    ("openrouter_top_p",             sa.Float(),   None),
    # Ollama
    ("ollama_top_p",                 sa.Float(),   None),
    ("ollama_top_k",                 sa.Integer(), None),
    ("ollama_repeat_penalty",        sa.Float(),   None),
]


def upgrade() -> None:
    conn = op.get_bind()
    table_exists = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name='global_settings'"
        )
    ).fetchone()
    if table_exists is None:
        return  # Fresh install — create_tables() handles all columns

    for col_name, col_type, default in _NEW_COLS:
        col_exists = conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns "
                f"WHERE table_name='global_settings' AND column_name='{col_name}'"
            )
        ).fetchone()
        if col_exists is None:
            kw = {"nullable": True}
            if default is not None:
                kw["server_default"] = default
            op.add_column("global_settings", sa.Column(col_name, col_type, **kw))


def downgrade() -> None:
    for col_name, _, _ in _NEW_COLS:
        op.drop_column("global_settings", col_name)
