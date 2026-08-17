"""API-specific Pydantic request/response schemas.

Kept deliberately separate from zeroshield.models (the core domain models) so
that the API's response shape can be curated and can evolve independently of
the core schema, per the Milestone 19 "do not simply return arbitrary
internal Python objects" requirement. Fields are plain str/float/bool - no
core business logic is implemented in this module.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from zeroshield.policies import ExecutionContext


class HealthResponse(BaseModel):
    status: str
    service: str


class ExperimentSummary(BaseModel):
    experiment_id: str
    title: str
    domain: str
    safety_level: str
    approval_status: str


class ExperimentListResponse(BaseModel):
    experiments: list[ExperimentSummary]


class CVESummary(BaseModel):
    cve_id: str
    cvss_score: float | None
    cisa_kev: bool


class ExperimentDetailResponse(BaseModel):
    experiment_id: str
    title: str
    domain: str
    description: str
    related_cves: list[CVESummary]
    failure_pattern: str
    root_cause: str
    vendor_mitigation: str
    mitigation_gap: str
    research_question: str
    hypothesis: str
    safety_level: str
    approval_status: str
    baseline_strategy: str
    mitigation_strategy: str


class ExecutionContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_context: ExecutionContext = Field(
        description=(
            "Safety-policy execution context. 'experiment_run' is the strict, real-world "
            "gate. 'local_unit_test' only relaxes the approval-status check (SAFE-004), "
            "intended for local demonstration of draft experiments only."
        )
    )


class ValidationResponse(BaseModel):
    experiment_id: str
    execution_context: str
    dataset_available: bool
    safety_passed: bool
    safety_reasons: list[str]
    overall_valid: bool


class JobSubmittedResponse(BaseModel):
    job_id: str
    experiment_id: str
    status: str


class JobResultSummary(BaseModel):
    baseline_run_id: str
    mitigation_run_id: str
    total_cases: int
    baseline_block_rate: float
    mitigation_block_rate: float
    block_rate_improvement: float
    evidence_location: str


class JobStatusResponse(BaseModel):
    job_id: str
    experiment_id: str
    execution_context: str
    status: str
    submitted_at: str
    updated_at: str
    result: JobResultSummary | None = None
    error: str | None = None


class MetricsSummary(BaseModel):
    processing_success_rate: float
    block_rate: float
    valid_acceptance_rate: float
    false_positive_rate: float
    false_negative_rate: float
    parser_reach_rate: float
    mean_latency_ms: float
    log_completeness_rate: float


class ResultsResponse(BaseModel):
    experiment_id: str
    baseline_run_id: str
    mitigation_run_id: str
    total_cases: int
    baseline_metrics: MetricsSummary
    mitigation_metrics: MetricsSummary
    block_rate_improvement: float
    latency_overhead_ms: float
    limitations: list[str]


class RunEvidenceSummary(BaseModel):
    run_id: str
    mode: str
    strategy_id: str
    started_at: str
    completed_at: str
    dataset_id: str
    dataset_sha256: str
    git_commit: str
    manifest_sha256: str
    integrity_verified: bool


class EvidenceResponse(BaseModel):
    experiment_id: str
    evidence_location: str
    baseline: RunEvidenceSummary
    mitigation: RunEvidenceSummary


class ErrorResponse(BaseModel):
    error: str
    detail: str


# -- Threat Intelligence & Prioritisation (V2 Phase 2) -----------------------


class VulnerabilitySummary(BaseModel):
    cve_id: str
    description: str | None
    cvss_score: float | None
    epss_score: float | None
    kev_listed: bool
    vendor: str | None
    domain_guess: str | None
    sources: list[str]
    last_updated_at: str


class VulnerabilityListResponse(BaseModel):
    vulnerabilities: list[VulnerabilitySummary]
    total: int
    limit: int
    offset: int


class VulnerabilitySourceDetail(BaseModel):
    source: str
    source_identifier: str | None
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    kev_listed: bool | None
    description: str | None
    references: list[str]
    first_seen_at: str
    last_seen_at: str


class VulnerabilityDetailResponse(VulnerabilitySummary):
    published_at: str | None
    last_modified_at: str | None
    cvss_vector: str | None
    cvss_version: str | None
    epss_percentile: float | None
    kev_date_added: str | None
    kev_due_date: str | None
    cwe_ids: list[str]
    references: list[str]
    source_records: list[VulnerabilitySourceDetail]


class VulnerabilityHistoryEntryResponse(BaseModel):
    source: str
    field: str
    old_value: str | None
    new_value: str | None
    observed_at: str


class VulnerabilityHistoryResponse(BaseModel):
    cve_id: str
    history: list[VulnerabilityHistoryEntryResponse]


class VendorAdvisoryResponse(BaseModel):
    advisory_id: str
    source: str
    cve_id: str | None
    title: str
    summary: str | None
    severity: str | None
    published_at: str | None
    updated_at: str | None
    references: list[str]


class VendorAdvisoryListResponse(BaseModel):
    cve_id: str
    advisories: list[VendorAdvisoryResponse]


class ValidationCandidateResponse(BaseModel):
    cve_id: str
    domain: str | None
    support_status: str
    priority_score: float
    priority_label: str
    explanation: list[str]
    existing_experiment_ids: list[str]
    generated_at: str


class PriorityQueueResponse(BaseModel):
    candidates: list[ValidationCandidateResponse]
    total: int
    limit: int
    offset: int


class ConnectorHealthResponse(BaseModel):
    source: str
    available: bool
    detail: str | None
    checked_at: str


class SourcesResponse(BaseModel):
    sources: list[ConnectorHealthResponse]


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(description="One of the registered VulnerabilitySourceName values, e.g. 'nvd'.")
    since: str | None = Field(
        default=None, description="ISO-8601 timestamp; omit for a source-defined default window."
    )


class SyncSubmittedResponse(BaseModel):
    sync_id: str
    source: str
    status: str


class SyncStatusResponse(BaseModel):
    sync_id: str
    source: str
    status: str
    since: str | None
    started_at: str
    completed_at: str | None
    fetched_count: int
    created_count: int
    updated_count: int
    unchanged_count: int
    failed_count: int
    error_summary: str | None


class SyncListResponse(BaseModel):
    syncs: list[SyncStatusResponse]


# -- Advanced Validation Platform (V2 Phase 3) -------------------------------


class DomainPackResponse(BaseModel):
    pack_id: str
    name: str
    version: str
    domain: str
    supported_failure_patterns: list[str]
    template_ids: list[str]
    allowed_strategy_ids: list[str]
    dataset_generator_id: str
    domain_metrics: list[str]
    compatibility: dict[str, str]


class DomainPackListResponse(BaseModel):
    domain_packs: list[DomainPackResponse]


class ValidationTemplateResponse(BaseModel):
    template_id: str
    version: str
    domain_pack_id: str
    name: str
    supported_failure_patterns: list[str]
    required_input_fields: list[str]
    allowed_baseline_strategies: list[str]
    allowed_mitigation_strategies: list[str]
    configurable_parameters: dict[str, Any]
    metrics_to_collect: list[str]
    safety_level: str


class ValidationTemplateListResponse(BaseModel):
    templates: list[ValidationTemplateResponse]


class GenerateDatasetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain_pack_id: str
    seed: int
    config: dict[str, Any] = Field(default_factory=dict)


class GenerateDatasetResponse(BaseModel):
    generator_id: str
    generator_version: str
    seed: int
    sha256: str
    test_set_id: str
    case_count: int
    cases_by_category: dict[str, int]


class CVEReferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    domain: str
    cvss_score: float | None = None
    cisa_kev: bool
    epss_score: float | None = None
    trust_boundary: str
    root_cause: str
    vendor_mitigation: str
    mitigation_gap: str
    source_urls: list[str]
    retrieved_date: str


class CreateExperimentVersionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    title: str
    description: str
    related_cves: list[CVEReferenceRequest] = Field(min_length=1)
    domain_pack_id: str
    template_id: str
    template_version: str
    dataset_config: dict[str, Any] = Field(default_factory=dict)
    seed: int
    failure_pattern: str
    root_cause: str
    vendor_mitigation: str
    mitigation_gap: str
    research_question: str
    hypothesis: str
    metrics_to_collect: list[str] | None = None
    # `created_by` is deliberately NOT a client-supplied field (V2 Phase 6) -
    # zeroshield.api.routes.studio.create_experiment_version sources it from
    # the authenticated session (CurrentUser.username). Trusting a
    # client-supplied identity string here is exactly the gap that would
    # make "a Researcher must not approve their own experiment" (Step 2)
    # trivially bypassable by lying about who created a draft.


class EditExperimentVersionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    description: str | None = None
    research_question: str | None = None
    hypothesis: str | None = None


class ApprovalActionRequest(BaseModel):
    """`actor` is deliberately NOT a field here (V2 Phase 6) - see
    CreateExperimentVersionRequest's `created_by` note; the actor of an
    approval transition is always the authenticated session, never
    client-supplied."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = None


class ApprovalDecisionResponse(BaseModel):
    version_id: str
    from_status: str
    to_status: str
    actor: str
    reason: str | None
    decided_at: str


class ExperimentVersionResponse(BaseModel):
    version_id: str
    experiment_id: str
    version_number: int
    status: str
    domain_pack_id: str
    template_id: str
    template_version: str
    created_by: str
    created_at: str
    updated_at: str


class ExperimentVersionListResponse(BaseModel):
    versions: list[ExperimentVersionResponse]


class JobListResponse(BaseModel):
    jobs: list[JobStatusResponse]


class DependencyHealthResponse(BaseModel):
    name: str
    available: bool
    detail: str | None
    checked_at: str


class SystemStatusResponse(BaseModel):
    dependencies: list[DependencyHealthResponse]


class VerdictResponse(BaseModel):
    experiment_id: str
    label: str
    reasons: list[str]
    thresholds_used: dict[str, float]
    failed_criteria: list[str]
    limitations: list[str]
    generated_at: str


# -- AI & Continuous Assurance (V2 Phase 5) -----------------------------------

class AssetResponse(BaseModel):
    asset_id: str
    name: str
    vendor: str
    product: str
    version: str | None
    environment: str
    exposure: str
    criticality: str
    active: bool
    created_at: str
    updated_at: str


class AssetListResponse(BaseModel):
    assets: list[AssetResponse]


class CreateAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    version: str | None = None
    environment: str = Field(min_length=1)
    exposure: str = Field(min_length=1)
    criticality: str = Field(min_length=1)
    active: bool = True


class UpdateAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    version: str | None = None
    environment: str | None = None
    exposure: str | None = None
    criticality: str | None = None
    active: bool | None = None


class ControlResponse(BaseModel):
    control_id: str
    name: str
    domain: str
    mitigation_strategy_id: str
    created_at: str


class ControlListResponse(BaseModel):
    controls: list[ControlResponse]


class ControlVersionResponse(BaseModel):
    version_id: str
    control_id: str
    version_label: str
    domain_pack_id: str
    template_id: str
    template_version: str
    created_at: str


class ControlVersionListResponse(BaseModel):
    versions: list[ControlVersionResponse]


class ControlValidationResponse(BaseModel):
    validation_id: str
    control_id: str
    version_id: str
    experiment_id: str
    baseline_run_id: str
    mitigation_run_id: str
    total_cases: int
    block_rate_improvement: float
    false_positive_rate: float
    false_negative_rate: float
    valid_acceptance_rate: float
    parser_reach_rate: float
    latency_overhead_ms: float
    verdict_label: str
    validated_at: str


class RegressionResultResponse(BaseModel):
    is_regression: bool
    reasons: list[str]
    thresholds_used: dict[str, float]


class ControlEffectivenessResponse(BaseModel):
    control_id: str
    current_version_id: str | None
    current_version_label: str | None
    validation_count_current_version: int
    total_validation_count: int
    mean_block_rate_improvement_current_version: float | None
    latest_verdict: str | None
    previous_verdict: str | None
    last_validated_at: str | None
    trend: list[ControlValidationResponse]
    comparability_note: str
    regression: RegressionResultResponse | None = None


class RevalidationCandidateResponse(BaseModel):
    candidate_id: str
    control_id: str
    experiment_id: str | None
    trigger_type: str
    trigger_detail: str
    status: str
    created_at: str
    reviewed_by: str | None
    reviewed_at: str | None
    review_note: str | None


class RevalidationCandidateListResponse(BaseModel):
    candidates: list[RevalidationCandidateResponse]


class RevalidationScanResponse(BaseModel):
    candidates_created: list[RevalidationCandidateResponse]
    controls_scanned: int


class CreateRevalidationCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    control_id: str = Field(min_length=1)
    experiment_id: str | None = None
    trigger_type: str = Field(min_length=1)
    trigger_detail: str = Field(min_length=1)


class RevalidationDecisionRequest(BaseModel):
    """`actor` is deliberately NOT a field here (V2 Phase 6) - see
    ApprovalActionRequest's docstring; the actor is always the authenticated
    session, never client-supplied."""

    model_config = ConfigDict(extra="forbid")
    note: str | None = None


class AIAssessmentResponse(BaseModel):
    assessment_id: str
    assessment_type: str
    subject_type: str
    subject_id: str
    payload: dict[str, Any]
    confidence: float
    reviewed: bool
    reviewed_by: str | None
    reviewed_at: str | None
    review_note: str | None
    created_at: str


class AIAssessmentListResponse(BaseModel):
    assessments: list[AIAssessmentResponse]


class ReviewAssessmentRequest(BaseModel):
    """`reviewed_by` is deliberately NOT a field here (V2 Phase 6) - see
    ApprovalActionRequest's docstring; the reviewer is always the
    authenticated session, never client-supplied."""

    model_config = ConfigDict(extra="forbid")
    note: str | None = None


class ExperimentDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_pack_id: str = Field(min_length=1)
    template_id: str = Field(min_length=1)


class CorrelatedVulnerabilityResponse(BaseModel):
    cve_id: str
    score: float
    explanation: list[str]
    shared_experiment_ids: list[str]


class CorrelationListResponse(BaseModel):
    cve_id: str
    correlations: list[CorrelatedVulnerabilityResponse]
    caveat: str


class AffectedAssetListResponse(BaseModel):
    cve_id: str
    assets: list[AssetResponse]


# -- Auth / RBAC / audit (V2 Phase 6) ------------------------------------------


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class UserResponse(BaseModel):
    user_id: str
    username: str
    role: str
    active: bool
    created_at: str
    updated_at: str


class LoginResponse(BaseModel):
    user: UserResponse


class UserListResponse(BaseModel):
    users: list[UserResponse]


class CreateUserRequest(BaseModel):
    """ADMIN-only (POST /users). `password` is validated for minimum length
    here (defense in depth alongside zeroshield.auth.passwords.
    MIN_PASSWORD_LENGTH) and never appears in any response, log line, or
    audit event - only its Argon2id hash is ever persisted."""

    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12)
    role: str = Field(description="One of: viewer, researcher, reviewer, admin.")


class UpdateUserRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(description="One of: viewer, researcher, reviewer, admin.")


class UpdateUserActiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: bool


class AuditEventResponse(BaseModel):
    audit_id: str
    occurred_at: str
    actor_user_id: str | None
    actor_username: str | None
    actor_role: str | None
    action: str
    target_type: str | None
    target_id: str | None
    request_id: str | None
    metadata: dict[str, Any]
    previous_state: dict[str, Any] | None
    new_state: dict[str, Any] | None


class AuditEventListResponse(BaseModel):
    events: list[AuditEventResponse]
    total: int
    limit: int
    offset: int
