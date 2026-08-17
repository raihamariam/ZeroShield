"""Lightweight, no-database checks that the ORM schema is what
PostgresRunRepository/VulnerabilityRepository and the Alembic migrations
(0001_create_runs_and_run_events.py, 0002_create_intelligence_tables.py)
expect - fast, run on every `pytest` invocation without needing Postgres.
"""

from zeroshield.db.base import Base
from zeroshield.db.models import RunEventORM, RunORM


def test_base_metadata_registers_all_expected_tables() -> None:
    assert set(Base.metadata.tables) == {
        "runs",
        "run_events",
        # V2 Phase 2: Threat Intelligence & Prioritisation
        "vulnerabilities",
        "vulnerability_sources",
        "vulnerability_history",
        "products",
        "affected_products",
        "vendor_advisories",
        "intelligence_syncs",
        "validation_candidates",
        # V2 Phase 3: Advanced Validation Platform
        "experiment_versions",
        "experiment_version_approvals",
        # V2 Phase 5: AI & Continuous Assurance
        "assets",
        "controls",
        "control_versions",
        "control_validations",
        "revalidation_candidates",
        "ai_assessments",
    }


def test_runs_table_columns() -> None:
    columns = {c.name for c in RunORM.__table__.columns}
    assert columns == {
        "job_id",
        "experiment_id",
        "execution_context",
        "current_status",
        "created_at",
        "updated_at",
    }
    assert RunORM.__table__.c.job_id.primary_key is True


def test_run_events_table_columns_and_foreign_key() -> None:
    columns = {c.name for c in RunEventORM.__table__.columns}
    assert columns == {"id", "job_id", "experiment_id", "event_type", "occurred_at", "detail"}
    fk_targets = {fk.target_fullname for fk in RunEventORM.__table__.c.job_id.foreign_keys}
    assert fk_targets == {"runs.job_id"}


def test_vulnerabilities_table_has_primary_key_cve_id() -> None:
    from zeroshield.db.models import VulnerabilityORM

    assert VulnerabilityORM.__table__.c.cve_id.primary_key is True


def test_vulnerability_sources_has_unique_cve_source_constraint() -> None:
    from zeroshield.db.models import VulnerabilitySourceORM

    constraint_names = {c.name for c in VulnerabilitySourceORM.__table__.constraints}
    assert "uq_vulnerability_sources_cve_source" in constraint_names


def test_validation_candidates_has_unique_cve_domain_constraint() -> None:
    from zeroshield.db.models import ValidationCandidateORM

    constraint_names = {c.name for c in ValidationCandidateORM.__table__.constraints}
    assert "uq_validation_candidates_cve_domain" in constraint_names


def test_experiment_versions_has_unique_id_number_constraint() -> None:
    from zeroshield.db.models import ExperimentVersionORM

    constraint_names = {c.name for c in ExperimentVersionORM.__table__.constraints}
    assert "uq_experiment_versions_id_number" in constraint_names
    assert ExperimentVersionORM.__table__.c.version_id.primary_key is True


def test_experiment_version_approvals_foreign_key() -> None:
    from zeroshield.db.models import ExperimentVersionApprovalORM

    fk_targets = {
        fk.target_fullname for fk in ExperimentVersionApprovalORM.__table__.c.version_id.foreign_keys
    }
    assert fk_targets == {"experiment_versions.version_id"}
