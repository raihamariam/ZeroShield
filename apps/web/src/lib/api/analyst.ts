import { apiFetch } from "./client";
import type {
  AIAssessmentListResponse,
  AIAssessmentResponse,
  CorrelationListResponse,
  ExperimentDraftRequest,
  ReviewAssessmentRequest,
} from "./types";

// -- AI Research Analyst (V2 Phase 5, Steps 2/5/6) - every POST here is advisory
// only: it persists an AIAssessmentRecord with reviewed=false and nothing else.
// See src/zeroshield/api/routes/analyst.py for the enforcement this mirrors.

export function classifyFailurePattern(cveId: string): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/analyst/failure-pattern`, {
    method: "POST",
  });
}

export function analyzeMitigationGap(cveId: string): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/analyst/mitigation-gap`, {
    method: "POST",
  });
}

export function getCorrelations(
  cveId: string,
  options: { cache?: RequestCache } = {}
): Promise<CorrelationListResponse> {
  return apiFetch<CorrelationListResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/correlations`, {
    cache: options.cache,
  });
}

export function summariseSimilarity(cveId: string): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/analyst/similar`, {
    method: "POST",
  });
}

export function recommendTemplate(cveId: string): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/analyst/template-recommendation`, {
    method: "POST",
  });
}

export function draftExperimentProposal(cveId: string, request: ExperimentDraftRequest): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/analyst/experiment-draft`, {
    method: "POST",
    body: request,
  });
}

export interface AssessmentListParams {
  subject_type?: string;
  subject_id?: string;
  assessment_type?: string;
  reviewed?: boolean;
  [key: string]: string | number | boolean | undefined;
}

export function listAssessments(
  params: AssessmentListParams = {},
  options: { cache?: RequestCache } = {}
): Promise<AIAssessmentListResponse> {
  return apiFetch<AIAssessmentListResponse>("/ai-assessments", { searchParams: params, cache: options.cache });
}

export function getAssessment(assessmentId: string, options: { cache?: RequestCache } = {}): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/ai-assessments/${encodeURIComponent(assessmentId)}`, { cache: options.cache });
}

export function reviewAssessment(assessmentId: string, request: ReviewAssessmentRequest): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/ai-assessments/${encodeURIComponent(assessmentId)}/review`, {
    method: "POST",
    body: request,
  });
}
