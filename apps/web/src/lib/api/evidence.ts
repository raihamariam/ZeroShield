import { apiFetch, apiUrl } from "./client";
import type { EvidenceResponse, ResultsResponse } from "./types";

export function getResults(
  experimentId: string,
  options: { cache?: RequestCache } = {}
): Promise<ResultsResponse> {
  return apiFetch<ResultsResponse>(`/experiments/${encodeURIComponent(experimentId)}/results`, {
    cache: options.cache,
  });
}

export function getEvidence(
  experimentId: string,
  options: { cache?: RequestCache } = {}
): Promise<EvidenceResponse> {
  return apiFetch<EvidenceResponse>(`/experiments/${encodeURIComponent(experimentId)}/evidence`, {
    cache: options.cache,
  });
}

/** Browser-only: same-origin URL for the evidence bundle zip download, for use as an
 * <a href> - the browser streams and saves it directly, nothing is buffered in the UI. */
export function evidenceBundleUrl(experimentId: string): string {
  return apiUrl(`/experiments/${encodeURIComponent(experimentId)}/evidence/bundle`);
}
