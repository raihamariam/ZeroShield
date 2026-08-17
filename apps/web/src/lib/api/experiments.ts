import { apiFetch } from "./client";
import type {
  ExecutionContext,
  ExperimentDetailResponse,
  ExperimentListResponse,
  JobSubmittedResponse,
  ValidationResponse,
  VerdictResponse,
} from "./types";

export function listExperiments(options: { cache?: RequestCache } = {}): Promise<ExperimentListResponse> {
  return apiFetch<ExperimentListResponse>("/experiments", { cache: options.cache });
}

export function getExperiment(
  experimentId: string,
  options: { cache?: RequestCache } = {}
): Promise<ExperimentDetailResponse> {
  return apiFetch<ExperimentDetailResponse>(`/experiments/${encodeURIComponent(experimentId)}`, {
    cache: options.cache,
  });
}

export function validateExperiment(
  experimentId: string,
  executionContext: ExecutionContext
): Promise<ValidationResponse> {
  return apiFetch<ValidationResponse>(`/experiments/${encodeURIComponent(experimentId)}/validate`, {
    method: "POST",
    body: { execution_context: executionContext },
  });
}

export function submitExperimentRun(
  experimentId: string,
  executionContext: ExecutionContext
): Promise<JobSubmittedResponse> {
  return apiFetch<JobSubmittedResponse>(`/experiments/${encodeURIComponent(experimentId)}/runs`, {
    method: "POST",
    body: { execution_context: executionContext },
  });
}

export function getExperimentVerdict(
  experimentId: string,
  options: { cache?: RequestCache } = {}
): Promise<VerdictResponse> {
  return apiFetch<VerdictResponse>(`/experiments/${encodeURIComponent(experimentId)}/verdict`, {
    cache: options.cache,
  });
}
