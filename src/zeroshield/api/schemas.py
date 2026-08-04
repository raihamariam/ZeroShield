"""API-specific Pydantic request/response schemas.

Kept deliberately separate from zeroshield.models (the core domain models) so
that the API's response shape can be curated and can evolve independently of
the core schema, per the Milestone 19 "do not simply return arbitrary
internal Python objects" requirement. Fields are plain str/float/bool - no
core business logic is implemented in this module.
"""

from pydantic import BaseModel, Field

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


class KeyMetrics(BaseModel):
    baseline_block_rate: float
    mitigation_block_rate: float
    baseline_valid_acceptance_rate: float
    mitigation_valid_acceptance_rate: float
    block_rate_improvement: float


class RunResponse(BaseModel):
    experiment_id: str
    baseline_run_id: str
    mitigation_run_id: str
    status: str
    safety_passed: bool
    total_cases: int
    key_metrics: KeyMetrics
    evidence_location: str


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
