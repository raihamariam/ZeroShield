/**
 * Mirrors src/zeroshield/api/schemas.py exactly - one type per Pydantic response/request
 * model. Never widen a field beyond what the backend actually returns; the backend is the
 * single source of truth for shape (see AGENTS.md-style rule: the UI never invents data).
 */

// -- Health / System (V2 Phase 1 + Phase 4) ----------------------------------

export interface HealthResponse {
  status: string;
  service: string;
}

export interface DependencyHealthResponse {
  name: string;
  available: boolean;
  detail: string | null;
  checked_at: string;
}

export interface SystemStatusResponse {
  dependencies: DependencyHealthResponse[];
}

// -- Experiments (V1 / Phase 1) -----------------------------------------------

export type SafetyLevel = "low" | "medium" | "high" | "critical";
export type ApprovalStatus =
  | "draft"
  | "pending_review"
  | "approved"
  | "revision_required"
  | "rejected"
  | "closed";
export type Domain = "VPN" | "TELECOM";

export interface ExperimentSummary {
  experiment_id: string;
  title: string;
  domain: string;
  safety_level: string;
  approval_status: string;
}

export interface ExperimentListResponse {
  experiments: ExperimentSummary[];
}

export interface CVESummary {
  cve_id: string;
  cvss_score: number | null;
  cisa_kev: boolean;
}

export interface ExperimentDetailResponse {
  experiment_id: string;
  title: string;
  domain: string;
  description: string;
  related_cves: CVESummary[];
  failure_pattern: string;
  root_cause: string;
  vendor_mitigation: string;
  mitigation_gap: string;
  research_question: string;
  hypothesis: string;
  safety_level: string;
  approval_status: string;
  baseline_strategy: string;
  mitigation_strategy: string;
}

export type ExecutionContext = "local_unit_test" | "experiment_run";

export interface ValidationResponse {
  experiment_id: string;
  execution_context: string;
  dataset_available: boolean;
  safety_passed: boolean;
  safety_reasons: string[];
  overall_valid: boolean;
}

export interface JobSubmittedResponse {
  job_id: string;
  experiment_id: string;
  status: string;
}

export interface JobResultSummary {
  baseline_run_id: string;
  mitigation_run_id: string;
  total_cases: number;
  baseline_block_rate: number;
  mitigation_block_rate: number;
  block_rate_improvement: number;
  evidence_location: string;
}

export type JobStatus = "queued" | "running" | "completed" | "failed" | "denied";

export interface JobStatusResponse {
  job_id: string;
  experiment_id: string;
  execution_context: string;
  status: JobStatus;
  submitted_at: string;
  updated_at: string;
  result: JobResultSummary | null;
  error: string | null;
}

export interface JobListResponse {
  jobs: JobStatusResponse[];
}

export interface MetricsSummary {
  processing_success_rate: number;
  block_rate: number;
  valid_acceptance_rate: number;
  false_positive_rate: number;
  false_negative_rate: number;
  parser_reach_rate: number;
  mean_latency_ms: number;
  log_completeness_rate: number;
}

export interface ResultsResponse {
  experiment_id: string;
  baseline_run_id: string;
  mitigation_run_id: string;
  total_cases: number;
  baseline_metrics: MetricsSummary;
  mitigation_metrics: MetricsSummary;
  block_rate_improvement: number;
  latency_overhead_ms: number;
  limitations: string[];
}

export interface RunEvidenceSummary {
  run_id: string;
  mode: string;
  strategy_id: string;
  started_at: string;
  completed_at: string;
  dataset_id: string;
  dataset_sha256: string;
  git_commit: string;
  manifest_sha256: string;
  integrity_verified: boolean;
}

export interface EvidenceResponse {
  experiment_id: string;
  evidence_location: string;
  baseline: RunEvidenceSummary;
  mitigation: RunEvidenceSummary;
}

export interface ApiErrorBody {
  error: string;
  detail: string;
}

// -- Threat Intelligence & Prioritisation (V2 Phase 2) ------------------------

export interface VulnerabilitySummary {
  cve_id: string;
  description: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  kev_listed: boolean;
  vendor: string | null;
  domain_guess: string | null;
  sources: string[];
  last_updated_at: string;
}

export interface VulnerabilityListResponse {
  vulnerabilities: VulnerabilitySummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface VulnerabilitySourceDetail {
  source: string;
  source_identifier: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  kev_listed: boolean | null;
  description: string | null;
  references: string[];
  first_seen_at: string;
  last_seen_at: string;
}

export interface VulnerabilityDetailResponse extends VulnerabilitySummary {
  published_at: string | null;
  last_modified_at: string | null;
  cvss_vector: string | null;
  cvss_version: string | null;
  epss_percentile: number | null;
  kev_date_added: string | null;
  kev_due_date: string | null;
  cwe_ids: string[];
  references: string[];
  source_records: VulnerabilitySourceDetail[];
}

export interface VulnerabilityHistoryEntryResponse {
  source: string;
  field: string;
  old_value: string | null;
  new_value: string | null;
  observed_at: string;
}

export interface VulnerabilityHistoryResponse {
  cve_id: string;
  history: VulnerabilityHistoryEntryResponse[];
}

export type SupportStatus = "supported" | "partially_supported" | "unsupported";

export interface ValidationCandidateResponse {
  cve_id: string;
  domain: string | null;
  support_status: SupportStatus;
  priority_score: number;
  priority_label: string;
  explanation: string[];
  existing_experiment_ids: string[];
  generated_at: string;
}

export interface PriorityQueueResponse {
  candidates: ValidationCandidateResponse[];
  total: number;
  limit: number;
  offset: number;
}

export interface ConnectorHealthResponse {
  source: string;
  available: boolean;
  detail: string | null;
  checked_at: string;
}

export interface SourcesResponse {
  sources: ConnectorHealthResponse[];
}

export interface SyncRequest {
  source: string;
  since?: string | null;
}

export interface SyncSubmittedResponse {
  sync_id: string;
  source: string;
  status: string;
}

export interface SyncStatusResponse {
  sync_id: string;
  source: string;
  status: string;
  since: string | null;
  started_at: string;
  completed_at: string | null;
  fetched_count: number;
  created_count: number;
  updated_count: number;
  unchanged_count: number;
  failed_count: number;
  error_summary: string | null;
}

export interface SyncListResponse {
  syncs: SyncStatusResponse[];
}

// -- Advanced Validation Platform (V2 Phase 3) ---------------------------------

export interface DomainPackResponse {
  pack_id: string;
  name: string;
  version: string;
  domain: string;
  supported_failure_patterns: string[];
  template_ids: string[];
  allowed_strategy_ids: string[];
  dataset_generator_id: string;
  domain_metrics: string[];
  compatibility: Record<string, string>;
}

export interface DomainPackListResponse {
  domain_packs: DomainPackResponse[];
}

export interface ValidationTemplateResponse {
  template_id: string;
  version: string;
  domain_pack_id: string;
  name: string;
  supported_failure_patterns: string[];
  required_input_fields: string[];
  allowed_baseline_strategies: string[];
  allowed_mitigation_strategies: string[];
  configurable_parameters: Record<string, unknown>;
  metrics_to_collect: string[];
  safety_level: string;
}

export interface ValidationTemplateListResponse {
  templates: ValidationTemplateResponse[];
}

export interface GenerateDatasetRequest {
  domain_pack_id: string;
  seed: number;
  config: Record<string, unknown>;
}

export interface GenerateDatasetResponse {
  generator_id: string;
  generator_version: string;
  seed: number;
  sha256: string;
  test_set_id: string;
  case_count: number;
  cases_by_category: Record<string, number>;
}

export interface CVEReferenceRequest {
  cve_id: string;
  domain: string;
  cvss_score?: number | null;
  cisa_kev: boolean;
  epss_score?: number | null;
  trust_boundary: string;
  root_cause: string;
  vendor_mitigation: string;
  mitigation_gap: string;
  source_urls: string[];
  retrieved_date: string;
}

export interface CreateExperimentVersionRequest {
  experiment_id: string;
  title: string;
  description: string;
  related_cves: CVEReferenceRequest[];
  domain_pack_id: string;
  template_id: string;
  template_version: string;
  dataset_config: Record<string, unknown>;
  seed: number;
  failure_pattern: string;
  root_cause: string;
  vendor_mitigation: string;
  mitigation_gap: string;
  research_question: string;
  hypothesis: string;
  // created_by is NOT a request field (V2 Phase 6) - the backend derives it
  // from the authenticated session, never a client-supplied name.
  metrics_to_collect?: string[] | null;
}

export interface EditExperimentVersionRequest {
  title?: string | null;
  description?: string | null;
  research_question?: string | null;
  hypothesis?: string | null;
}

export interface ApprovalActionRequest {
  // actor is NOT a request field (V2 Phase 6) - always the authenticated session.
  reason?: string | null;
}

export interface ApprovalDecisionResponse {
  version_id: string;
  from_status: string;
  to_status: string;
  actor: string;
  reason: string | null;
  decided_at: string;
}

export type ExperimentVersionStatus =
  | "draft"
  | "ready_for_review"
  | "under_review"
  | "approved"
  | "rejected"
  | "retired";

export interface ExperimentVersionResponse {
  version_id: string;
  experiment_id: string;
  version_number: number;
  status: ExperimentVersionStatus;
  domain_pack_id: string;
  template_id: string;
  template_version: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ExperimentVersionListResponse {
  versions: ExperimentVersionResponse[];
}

export interface VerdictResponse {
  experiment_id: string;
  label: string;
  reasons: string[];
  thresholds_used: Record<string, number>;
  failed_criteria: string[];
  limitations: string[];
  generated_at: string;
}

// -- Run lifecycle events (V2 Phase 1 RunEventType, streamed in Phase 4) ------

export type RunEventType =
  | "queued"
  | "preparing"
  | "safety_check"
  | "running_baseline"
  | "running_mitigation"
  | "analysing"
  | "generating_evidence"
  | "completed"
  | "denied"
  | "failed";

export interface RunEventPayload {
  event_type: RunEventType;
  occurred_at: string;
  detail: Record<string, unknown> | null;
}

export interface JobTerminalPayload {
  job_status: JobStatus;
  error: string | null;
}

// -- AI & Continuous Assurance (V2 Phase 5) ------------------------------------

export interface VendorAdvisoryResponse {
  advisory_id: string;
  source: string;
  cve_id: string | null;
  title: string;
  summary: string | null;
  severity: string | null;
  published_at: string | null;
  updated_at: string | null;
  references: string[];
}

export interface VendorAdvisoryListResponse {
  cve_id: string;
  advisories: VendorAdvisoryResponse[];
}

export interface CorrelatedVulnerabilityResponse {
  cve_id: string;
  score: number;
  explanation: string[];
  shared_experiment_ids: string[];
}

export interface CorrelationListResponse {
  cve_id: string;
  correlations: CorrelatedVulnerabilityResponse[];
  caveat: string;
}

/** AI-generated structured output entering application state (Step 2) - every
 * shape here always carries confidence/rationale/source_ids/provider/model/
 * generated_at (see src/zeroshield/ai/schemas.py's AIAssessmentBase). `payload`
 * on AIAssessmentResponse below is untyped JSON on the wire (the backend
 * validates it server-side against one of these before ever persisting it),
 * so these are read-time hints for rendering, not a wire contract of their own. */
export interface AIAssessmentBasePayload {
  confidence: number;
  rationale: string;
  source_ids: string[];
  provider: string;
  model: string;
  generated_at: string;
}

export interface FailurePatternAssessmentPayload extends AIAssessmentBasePayload {
  cve_id: string;
  domain: string | null;
  failure_pattern: string;
  supporting_evidence: string[];
}

export interface MitigationGapAssessmentPayload extends AIAssessmentBasePayload {
  cve_id: string;
  gaps: string[];
}

export interface SimilarVulnerabilityRecommendationPayload extends AIAssessmentBasePayload {
  cve_id: string;
  similar_cve_ids: string[];
  caveat: string;
}

export interface ValidationTemplateRecommendationPayload extends AIAssessmentBasePayload {
  cve_id: string;
  domain_pack_id: string;
  template_id: string;
  template_version: string;
}

export interface ExperimentDraftSuggestionPayload extends AIAssessmentBasePayload {
  cve_id: string;
  title: string;
  research_question: string;
  hypothesis: string;
  trust_boundary: string;
  vendor_mitigation: string;
  mitigation_gap: string;
}

export type AssessmentType =
  | "failure_pattern"
  | "mitigation_gap"
  | "similarity"
  | "template_recommendation"
  | "experiment_draft";

export interface AIAssessmentResponse {
  assessment_id: string;
  assessment_type: AssessmentType | string;
  subject_type: string;
  subject_id: string;
  payload: Record<string, unknown>;
  confidence: number;
  reviewed: boolean;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  created_at: string;
}

export interface AIAssessmentListResponse {
  assessments: AIAssessmentResponse[];
}

export interface ReviewAssessmentRequest {
  // reviewed_by is NOT a request field (V2 Phase 6) - always the authenticated session.
  note?: string | null;
}

export interface ExperimentDraftRequest {
  domain_pack_id: string;
  template_id: string;
}

export interface AssetResponse {
  asset_id: string;
  name: string;
  vendor: string;
  product: string;
  version: string | null;
  environment: string;
  exposure: string;
  criticality: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AssetListResponse {
  assets: AssetResponse[];
}

export interface AffectedAssetListResponse {
  cve_id: string;
  assets: AssetResponse[];
}

export interface CreateAssetRequest {
  asset_id: string;
  name: string;
  vendor: string;
  product: string;
  version?: string | null;
  environment: string;
  exposure: string;
  criticality: string;
  active?: boolean;
}

export interface UpdateAssetRequest {
  name?: string | null;
  version?: string | null;
  environment?: string | null;
  exposure?: string | null;
  criticality?: string | null;
  active?: boolean | null;
}

export interface ControlResponse {
  control_id: string;
  name: string;
  domain: string;
  mitigation_strategy_id: string;
  created_at: string;
}

export interface ControlListResponse {
  controls: ControlResponse[];
}

export interface ControlVersionResponse {
  version_id: string;
  control_id: string;
  version_label: string;
  domain_pack_id: string;
  template_id: string;
  template_version: string;
  created_at: string;
}

export interface ControlVersionListResponse {
  versions: ControlVersionResponse[];
}

export interface ControlValidationResponse {
  validation_id: string;
  control_id: string;
  version_id: string;
  experiment_id: string;
  baseline_run_id: string;
  mitigation_run_id: string;
  total_cases: number;
  block_rate_improvement: number;
  false_positive_rate: number;
  false_negative_rate: number;
  valid_acceptance_rate: number;
  parser_reach_rate: number;
  latency_overhead_ms: number;
  verdict_label: string;
  validated_at: string;
}

export interface RegressionResultResponse {
  is_regression: boolean;
  reasons: string[];
  thresholds_used: Record<string, number>;
}

export interface ControlEffectivenessResponse {
  control_id: string;
  current_version_id: string | null;
  current_version_label: string | null;
  validation_count_current_version: number;
  total_validation_count: number;
  mean_block_rate_improvement_current_version: number | null;
  latest_verdict: string | null;
  previous_verdict: string | null;
  last_validated_at: string | null;
  trend: ControlValidationResponse[];
  comparability_note: string;
  regression: RegressionResultResponse | null;
}

export type RevalidationTriggerType =
  | "new_related_cve"
  | "kev_state_change"
  | "epss_material_change"
  | "advisory_update"
  | "version_change"
  | "scheduled"
  | "regression";

export type RevalidationStatus = "pending" | "approved" | "dismissed";

export interface RevalidationCandidateResponse {
  candidate_id: string;
  control_id: string;
  experiment_id: string | null;
  trigger_type: RevalidationTriggerType | string;
  trigger_detail: string;
  status: RevalidationStatus | string;
  created_at: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
}

export interface RevalidationCandidateListResponse {
  candidates: RevalidationCandidateResponse[];
}

export interface RevalidationScanResponse {
  candidates_created: RevalidationCandidateResponse[];
  controls_scanned: number;
}

export interface CreateRevalidationCandidateRequest {
  control_id: string;
  experiment_id?: string | null;
  trigger_type: string;
  trigger_detail: string;
}

export interface RevalidationDecisionRequest {
  // actor is NOT a request field (V2 Phase 6) - always the authenticated session.
  note?: string | null;
}

// -- Auth / RBAC / audit (V2 Phase 6) ------------------------------------------

export type Role = "viewer" | "researcher" | "reviewer" | "admin";

export interface LoginRequest {
  username: string;
  password: string;
}

export interface UserResponse {
  user_id: string;
  username: string;
  role: Role;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface LoginResponse {
  user: UserResponse;
}

export interface UserListResponse {
  users: UserResponse[];
}

export interface CreateUserRequest {
  username: string;
  password: string;
  role: Role;
}

export interface UpdateUserRoleRequest {
  role: Role;
}

export interface UpdateUserActiveRequest {
  active: boolean;
}

export interface AuditEventResponse {
  audit_id: string;
  occurred_at: string;
  actor_user_id: string | null;
  actor_username: string | null;
  actor_role: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  request_id: string | null;
  metadata: Record<string, unknown>;
  previous_state: Record<string, unknown> | null;
  new_state: Record<string, unknown> | null;
}

export interface AuditEventListResponse {
  events: AuditEventResponse[];
  total: number;
  limit: number;
  offset: number;
}
