"""create AI & Continuous Assurance tables (V2 Phase 5)

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-17

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=False),
        sa.Column("product", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("environment", sa.String(), nullable=False),
        sa.Column("exposure", sa.String(), nullable=False),
        sa.Column("criticality", sa.String(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_assets_vendor", "assets", ["vendor"])
    op.create_index("ix_assets_product", "assets", ["product"])
    op.create_index("ix_assets_criticality", "assets", ["criticality"])
    op.create_index("ix_assets_active", "assets", ["active"])

    op.create_table(
        "controls",
        sa.Column("control_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("mitigation_strategy_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_controls_domain", "controls", ["domain"])

    op.create_table(
        "control_versions",
        sa.Column("version_id", sa.String(), primary_key=True),
        sa.Column("control_id", sa.String(), sa.ForeignKey("controls.control_id"), nullable=False),
        sa.Column("version_label", sa.String(), nullable=False),
        sa.Column("domain_pack_id", sa.String(), nullable=False),
        sa.Column("template_id", sa.String(), nullable=False),
        sa.Column("template_version", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("control_id", "version_label", name="uq_control_versions_control_label"),
    )
    op.create_index("ix_control_versions_control_id", "control_versions", ["control_id"])

    op.create_table(
        "control_validations",
        sa.Column("validation_id", sa.String(), primary_key=True),
        sa.Column("control_id", sa.String(), sa.ForeignKey("controls.control_id"), nullable=False),
        sa.Column("version_id", sa.String(), sa.ForeignKey("control_versions.version_id"), nullable=False),
        sa.Column("experiment_id", sa.String(), nullable=False),
        sa.Column("baseline_run_id", sa.String(), nullable=False),
        sa.Column("mitigation_run_id", sa.String(), nullable=False),
        sa.Column("total_cases", sa.Integer(), nullable=False),
        sa.Column("block_rate_improvement", sa.Float(), nullable=False),
        sa.Column("false_positive_rate", sa.Float(), nullable=False),
        sa.Column("false_negative_rate", sa.Float(), nullable=False),
        sa.Column("valid_acceptance_rate", sa.Float(), nullable=False),
        sa.Column("parser_reach_rate", sa.Float(), nullable=False),
        sa.Column("latency_overhead_ms", sa.Float(), nullable=False),
        sa.Column("verdict_label", sa.String(), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_control_validations_control_id", "control_validations", ["control_id"])
    op.create_index("ix_control_validations_version_id", "control_validations", ["version_id"])
    op.create_index("ix_control_validations_experiment_id", "control_validations", ["experiment_id"])
    op.create_index("ix_control_validations_validated_at", "control_validations", ["validated_at"])

    op.create_table(
        "revalidation_candidates",
        sa.Column("candidate_id", sa.String(), primary_key=True),
        sa.Column("control_id", sa.String(), sa.ForeignKey("controls.control_id"), nullable=False),
        sa.Column("experiment_id", sa.String(), nullable=True),
        sa.Column("trigger_type", sa.String(), nullable=False),
        sa.Column("trigger_detail", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_by", sa.String(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.String(), nullable=True),
    )
    op.create_index("ix_revalidation_candidates_control_id", "revalidation_candidates", ["control_id"])
    op.create_index("ix_revalidation_candidates_trigger_type", "revalidation_candidates", ["trigger_type"])
    op.create_index("ix_revalidation_candidates_status", "revalidation_candidates", ["status"])

    op.create_table(
        "ai_assessments",
        sa.Column("assessment_id", sa.String(), primary_key=True),
        sa.Column("assessment_type", sa.String(), nullable=False),
        sa.Column("subject_type", sa.String(), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reviewed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reviewed_by", sa.String(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_assessments_assessment_type", "ai_assessments", ["assessment_type"])
    op.create_index("ix_ai_assessments_subject_type", "ai_assessments", ["subject_type"])
    op.create_index("ix_ai_assessments_subject_id", "ai_assessments", ["subject_id"])
    op.create_index("ix_ai_assessments_reviewed", "ai_assessments", ["reviewed"])
    op.create_index("ix_ai_assessments_created_at", "ai_assessments", ["created_at"])


def downgrade() -> None:
    op.drop_table("ai_assessments")
    op.drop_table("revalidation_candidates")
    op.drop_table("control_validations")
    op.drop_table("control_versions")
    op.drop_table("controls")
    op.drop_table("assets")
