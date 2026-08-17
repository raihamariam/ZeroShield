"""create Experiment Studio tables (V2 Phase 3)

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-17

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "experiment_versions",
        sa.Column("version_id", sa.String(), primary_key=True),
        sa.Column("experiment_id", sa.String(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("domain_pack_id", sa.String(), nullable=False),
        sa.Column("template_id", sa.String(), nullable=False),
        sa.Column("template_version", sa.String(), nullable=False),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("dataset_provenance", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("experiment_id", "version_number", name="uq_experiment_versions_id_number"),
    )
    op.create_index("ix_experiment_versions_experiment_id", "experiment_versions", ["experiment_id"])
    op.create_index("ix_experiment_versions_status", "experiment_versions", ["status"])

    op.create_table(
        "experiment_version_approvals",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "version_id", sa.String(), sa.ForeignKey("experiment_versions.version_id"), nullable=False
        ),
        sa.Column("from_status", sa.String(), nullable=False),
        sa.Column("to_status", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_experiment_version_approvals_version_id", "experiment_version_approvals", ["version_id"]
    )


def downgrade() -> None:
    op.drop_table("experiment_version_approvals")
    op.drop_table("experiment_versions")
