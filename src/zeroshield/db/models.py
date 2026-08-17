"""ORM models for the run lifecycle system-of-record (Phase 1), the
threat-intelligence system of record (Phase 2: `vulnerabilities`,
`vulnerability_sources`, `vulnerability_history`, `products`,
`affected_products`, `vendor_advisories`, `intelligence_syncs`,
`validation_candidates`), Experiment Studio's versioned drafts/approvals
(Phase 3: `experiment_versions`, `experiment_version_approvals`), AI &
Continuous Assurance (Phase 5: `assets`, `controls`, `control_versions`,
`control_validations`, `revalidation_candidates`, `ai_assessments` - see
zeroshield.assurance.models for what each one means), and Hardening & Local
V2 Release (Phase 6: `users`, `sessions`, `audit_events` - see
zeroshield.auth.models/zeroshield.audit.models).

`runs` holds one row per job (keyed by the API-generated job_id, see
zeroshield.services.job_store), tracking its most recent status. `run_events`
holds the full, append-only audit trail behind that status - one row per
RunEventType transition, per the V2 Improvement Plan §4.5/§4.7 (Experiment
Lifecycle / Data and Evidence Architecture). Neither table stores evidence
content or safety decisions - those remain in EvidenceManifest/PolicyDecision,
persisted via EvidenceRepository, never duplicated here.

The Phase 2 tables mirror zeroshield.models.vulnerability's Pydantic domain
models one-for-one - see that module's docstring for why they are distinct
from CVEReference/ExperimentDefinition. `vulnerabilities` is the current
merged view; `vulnerability_sources` is one row per (cve_id, source) holding
that source's latest normalised contribution (provenance); `vulnerability_history`
is the append-only, change-detected field-level log Step 6 requires for
"what was known at time X" queries.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from zeroshield.db.base import Base

_UTCDateTime = DateTime(timezone=True)


class RunORM(Base):
    __tablename__ = "runs"

    job_id: Mapped[str] = mapped_column(String, primary_key=True)
    experiment_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    execution_context: Mapped[str] = mapped_column(String, nullable=False)
    current_status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)

    events: Mapped[list["RunEventORM"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="RunEventORM.id"
    )


class RunEventORM(Base):
    __tablename__ = "run_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("runs.job_id"), nullable=False, index=True)
    experiment_id: Mapped[str] = mapped_column(String, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    run: Mapped["RunORM"] = relationship(back_populates="events")


class VulnerabilityORM(Base):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_date: Mapped[str | None] = mapped_column(String, nullable=True)
    kev_listed: Mapped[bool] = mapped_column(nullable=False, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String, nullable=True)
    kev_due_date: Mapped[str | None] = mapped_column(String, nullable=True)
    kev_known_ransomware: Mapped[str | None] = mapped_column(String, nullable=True)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    domain_guess: Mapped[str | None] = mapped_column(String, nullable=True)
    zero_click_relevance: Mapped[str | None] = mapped_column(String, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    sources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    last_updated_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class VulnerabilitySourceORM(Base):
    """One row per (cve_id, source) - see zeroshield.models.vulnerability.VulnerabilitySourceRecord."""

    __tablename__ = "vulnerability_sources"
    __table_args__ = (UniqueConstraint("cve_id", "source", name="uq_vulnerability_sources_cve_source"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String, nullable=False)
    source_identifier: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_listed: Mapped[bool | None] = mapped_column(nullable=True)
    kev_date_added: Mapped[str | None] = mapped_column(String, nullable=True)
    kev_due_date: Mapped[str | None] = mapped_column(String, nullable=True)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class VulnerabilityHistoryORM(Base):
    """Append-only, change-detected field-level log - see
    zeroshield.models.vulnerability.VulnerabilityHistoryEntry and Step 6."""

    __tablename__ = "vulnerability_history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String, nullable=False)
    field: Mapped[str] = mapped_column(String, nullable=False)
    old_value: Mapped[str | None] = mapped_column(String, nullable=True)
    new_value: Mapped[str | None] = mapped_column(String, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class ProductORM(Base):
    __tablename__ = "products"
    __table_args__ = (UniqueConstraint("vendor", "name", name="uq_products_vendor_name"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    vendor: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    cpe: Mapped[str | None] = mapped_column(String, nullable=True)


class AffectedProductORM(Base):
    __tablename__ = "affected_products"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"), nullable=False, index=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), nullable=False)
    version_range: Mapped[str | None] = mapped_column(String, nullable=True)


class VendorAdvisoryORM(Base):
    __tablename__ = "vendor_advisories"

    advisory_id: Mapped[str] = mapped_column(String, primary_key=True)
    source: Mapped[str] = mapped_column(String, nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class IntelligenceSyncORM(Base):
    __tablename__ = "intelligence_syncs"

    sync_id: Mapped[str] = mapped_column(String, primary_key=True)
    source: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
    since: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    started_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    fetched_count: Mapped[int] = mapped_column(nullable=False, default=0)
    created_count: Mapped[int] = mapped_column(nullable=False, default=0)
    updated_count: Mapped[int] = mapped_column(nullable=False, default=0)
    unchanged_count: Mapped[int] = mapped_column(nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(nullable=False, default=0)
    error_summary: Mapped[str | None] = mapped_column(String, nullable=True)


class ValidationCandidateORM(Base):
    """One row per (cve_id, domain) - upserted each time priority is recomputed
    (zeroshield.intelligence.candidates), not append-only history."""

    __tablename__ = "validation_candidates"
    __table_args__ = (UniqueConstraint("cve_id", "domain", name="uq_validation_candidates_cve_domain"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"), nullable=False, index=True)
    domain: Mapped[str | None] = mapped_column(String, nullable=True)
    support_status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    priority_label: Mapped[str] = mapped_column(String, nullable=False, index=True)
    explanation: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    existing_experiment_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    generated_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class ExperimentVersionORM(Base):
    """One row per (experiment_id, version_number) - see
    zeroshield.models.experiment_version.ExperimentVersion. `definition`
    stores the full ExperimentDefinition JSON (the trusted-core payload);
    `status` is Experiment Studio's own workflow state
    (ExperimentVersionStatus), never the same field as
    definition["approval_status"] even though the two are kept in lockstep by
    zeroshield.studio.approval."""

    __tablename__ = "experiment_versions"
    __table_args__ = (
        UniqueConstraint("experiment_id", "version_number", name="uq_experiment_versions_id_number"),
    )

    version_id: Mapped[str] = mapped_column(String, primary_key=True)
    experiment_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    version_number: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    domain_pack_id: Mapped[str] = mapped_column(String, nullable=False)
    template_id: Mapped[str] = mapped_column(String, nullable=False)
    template_version: Mapped[str] = mapped_column(String, nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    dataset_provenance: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class ExperimentVersionApprovalORM(Base):
    """Append-only approval-decision log - see
    zeroshield.models.experiment_version.ApprovalDecision."""

    __tablename__ = "experiment_version_approvals"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    version_id: Mapped[str] = mapped_column(
        ForeignKey("experiment_versions.version_id"), nullable=False, index=True
    )
    from_status: Mapped[str] = mapped_column(String, nullable=False)
    to_status: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class AssetORM(Base):
    """Step 7's deliberately small asset inventory - see zeroshield.assurance.models.Asset."""

    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    vendor: Mapped[str] = mapped_column(String, nullable=False, index=True)
    product: Mapped[str] = mapped_column(String, nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    environment: Mapped[str] = mapped_column(String, nullable=False)
    exposure: Mapped[str] = mapped_column(String, nullable=False)
    criticality: Mapped[str] = mapped_column(String, nullable=False, index=True)
    active: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class ControlORM(Base):
    """One row per (domain, mitigation_strategy) - see
    zeroshield.assurance.models.Control and .repository.control_id_for."""

    __tablename__ = "controls"

    control_id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    domain: Mapped[str] = mapped_column(String, nullable=False, index=True)
    mitigation_strategy_id: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class ControlVersionORM(Base):
    __tablename__ = "control_versions"
    __table_args__ = (UniqueConstraint("control_id", "version_label", name="uq_control_versions_control_label"),)

    version_id: Mapped[str] = mapped_column(String, primary_key=True)
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.control_id"), nullable=False, index=True)
    version_label: Mapped[str] = mapped_column(String, nullable=False)
    domain_pack_id: Mapped[str] = mapped_column(String, nullable=False)
    template_id: Mapped[str] = mapped_column(String, nullable=False)
    template_version: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class ControlValidationORM(Base):
    """Append-only - see zeroshield.assurance.models.ControlValidation.
    Never updated or deleted once written."""

    __tablename__ = "control_validations"

    validation_id: Mapped[str] = mapped_column(String, primary_key=True)
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.control_id"), nullable=False, index=True)
    version_id: Mapped[str] = mapped_column(ForeignKey("control_versions.version_id"), nullable=False, index=True)
    experiment_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    baseline_run_id: Mapped[str] = mapped_column(String, nullable=False)
    mitigation_run_id: Mapped[str] = mapped_column(String, nullable=False)
    total_cases: Mapped[int] = mapped_column(nullable=False)
    block_rate_improvement: Mapped[float] = mapped_column(Float, nullable=False)
    false_positive_rate: Mapped[float] = mapped_column(Float, nullable=False)
    false_negative_rate: Mapped[float] = mapped_column(Float, nullable=False)
    valid_acceptance_rate: Mapped[float] = mapped_column(Float, nullable=False)
    parser_reach_rate: Mapped[float] = mapped_column(Float, nullable=False)
    latency_overhead_ms: Mapped[float] = mapped_column(Float, nullable=False)
    verdict_label: Mapped[str] = mapped_column(String, nullable=False)
    validated_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False, index=True)


class RevalidationCandidateORM(Base):
    """See zeroshield.assurance.models.RevalidationCandidate - `status`
    only ever changes via an explicit human review action (Step 11: "Do not
    silently execute arbitrary AI-created revalidations")."""

    __tablename__ = "revalidation_candidates"

    candidate_id: Mapped[str] = mapped_column(String, primary_key=True)
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.control_id"), nullable=False, index=True)
    experiment_id: Mapped[str | None] = mapped_column(String, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    trigger_detail: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    review_note: Mapped[str | None] = mapped_column(String, nullable=True)


class AIAssessmentORM(Base):
    """See zeroshield.assurance.models.AIAssessmentRecord. `payload` is the
    full JSON dump of whichever zeroshield.ai.schemas model produced this
    row - kept as JSON (not one column per assessment type) since the
    schema shape varies by assessment_type and this table is a generic
    audit/review log, not the source of truth for any downstream decision."""

    __tablename__ = "ai_assessments"

    assessment_id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reviewed: Mapped[bool] = mapped_column(nullable=False, default=False, index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    review_note: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False, index=True)


class UserORM(Base):
    """See zeroshield.auth.models.User/UserWithCredentials. `password_hash`
    never leaves this module boundary - zeroshield.auth.repository is the
    only code that reads this column."""

    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String, primary_key=True)
    username: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, index=True)
    active: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)
    failed_login_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(_UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)


class SessionORM(Base):
    """`session_id` is the SHA-256 hex digest of the raw cookie token, never
    the raw token - see zeroshield.auth.models.SessionRecord's docstring."""

    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.user_id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False, index=True)
    last_used_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)


class AuditEventORM(Base):
    """Append-only (Phase 6, Step 3) - no code path in this application ever
    updates or deletes a row here; see zeroshield.audit.service for the sole
    writer. `actor_username`/`actor_role` are snapshotted at write time
    (denormalised, not a live join to `users`) so an event remains a
    faithful historical record even if a user is later renamed or their role
    changes. `metadata_json`/`previous_state`/`new_state` must never contain
    a secret (password, session token, API key) - callers are responsible
    for redaction before calling zeroshield.audit.service.record()."""

    __tablename__ = "audit_events"

    audit_id: Mapped[str] = mapped_column(String, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(_UTCDateTime, nullable=False, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    actor_username: Mapped[str | None] = mapped_column(String, nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String, nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    target_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    request_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    previous_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    new_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
