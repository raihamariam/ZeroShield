"""create threat-intelligence tables (V2 Phase 2)

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-17

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("cve_id", sa.String(), primary_key=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(), nullable=True),
        sa.Column("cvss_version", sa.String(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("epss_date", sa.String(), nullable=True),
        sa.Column("kev_listed", sa.Boolean(), nullable=False),
        sa.Column("kev_date_added", sa.String(), nullable=True),
        sa.Column("kev_due_date", sa.String(), nullable=True),
        sa.Column("kev_known_ransomware", sa.String(), nullable=True),
        sa.Column("cwe_ids", sa.JSON(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=True),
        sa.Column("domain_guess", sa.String(), nullable=True),
        sa.Column("zero_click_relevance", sa.String(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "vulnerability_sources",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(), sa.ForeignKey("vulnerabilities.cve_id"), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("source_identifier", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(), nullable=True),
        sa.Column("cvss_version", sa.String(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("kev_listed", sa.Boolean(), nullable=True),
        sa.Column("kev_date_added", sa.String(), nullable=True),
        sa.Column("kev_due_date", sa.String(), nullable=True),
        sa.Column("cwe_ids", sa.JSON(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("cve_id", "source", name="uq_vulnerability_sources_cve_source"),
    )
    op.create_index("ix_vulnerability_sources_cve_id", "vulnerability_sources", ["cve_id"])

    op.create_table(
        "vulnerability_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(), sa.ForeignKey("vulnerabilities.cve_id"), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("field", sa.String(), nullable=False),
        sa.Column("old_value", sa.String(), nullable=True),
        sa.Column("new_value", sa.String(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vulnerability_history_cve_id", "vulnerability_history", ["cve_id"])

    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("vendor", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("cpe", sa.String(), nullable=True),
        sa.UniqueConstraint("vendor", "name", name="uq_products_vendor_name"),
    )

    op.create_table(
        "affected_products",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(), sa.ForeignKey("vulnerabilities.cve_id"), nullable=False),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=False),
        sa.Column("version_range", sa.String(), nullable=True),
    )
    op.create_index("ix_affected_products_cve_id", "affected_products", ["cve_id"])

    op.create_table(
        "vendor_advisories",
        sa.Column("advisory_id", sa.String(), primary_key=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("summary", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
    )
    op.create_index("ix_vendor_advisories_cve_id", "vendor_advisories", ["cve_id"])

    op.create_table(
        "intelligence_syncs",
        sa.Column("sync_id", sa.String(), primary_key=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fetched_count", sa.Integer(), nullable=False),
        sa.Column("created_count", sa.Integer(), nullable=False),
        sa.Column("updated_count", sa.Integer(), nullable=False),
        sa.Column("unchanged_count", sa.Integer(), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("error_summary", sa.String(), nullable=True),
    )
    op.create_index("ix_intelligence_syncs_source", "intelligence_syncs", ["source"])

    op.create_table(
        "validation_candidates",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(), sa.ForeignKey("vulnerabilities.cve_id"), nullable=False),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("support_status", sa.String(), nullable=False),
        sa.Column("priority_score", sa.Float(), nullable=False),
        sa.Column("priority_label", sa.String(), nullable=False),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("existing_experiment_ids", sa.JSON(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("cve_id", "domain", name="uq_validation_candidates_cve_domain"),
    )
    op.create_index("ix_validation_candidates_cve_id", "validation_candidates", ["cve_id"])
    op.create_index("ix_validation_candidates_support_status", "validation_candidates", ["support_status"])
    op.create_index("ix_validation_candidates_priority_score", "validation_candidates", ["priority_score"])
    op.create_index("ix_validation_candidates_priority_label", "validation_candidates", ["priority_label"])


def downgrade() -> None:
    op.drop_table("validation_candidates")
    op.drop_table("intelligence_syncs")
    op.drop_table("vendor_advisories")
    op.drop_table("affected_products")
    op.drop_table("products")
    op.drop_table("vulnerability_history")
    op.drop_table("vulnerability_sources")
    op.drop_table("vulnerabilities")
