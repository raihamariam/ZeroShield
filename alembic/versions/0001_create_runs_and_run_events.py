"""create runs and run_events tables

Revision ID: 0001
Revises:
Create Date: 2026-08-17

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("experiment_id", sa.String(), nullable=False),
        sa.Column("execution_context", sa.String(), nullable=False),
        sa.Column("current_status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_runs_experiment_id", "runs", ["experiment_id"])

    op.create_table(
        "run_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(), sa.ForeignKey("runs.job_id"), nullable=False),
        sa.Column("experiment_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
    )
    op.create_index("ix_run_events_job_id", "run_events", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_run_events_job_id", table_name="run_events")
    op.drop_table("run_events")
    op.drop_index("ix_runs_experiment_id", table_name="runs")
    op.drop_table("runs")
