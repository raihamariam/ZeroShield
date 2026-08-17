import { apiFetch } from "./client";
import type {
  CreateRevalidationCandidateRequest,
  RevalidationCandidateListResponse,
  RevalidationCandidateResponse,
  RevalidationDecisionRequest,
  RevalidationScanResponse,
} from "./types";

// -- Revalidation queue (V2 Phase 5, Step 11). Nothing here ever executes a run:
// approve()/dismiss() only change a candidate's status; the actual run is a
// separate, ordinary POST /experiments/{id}/runs (or /experiment-versions/{id}/runs).

export function scanForRevalidation(): Promise<RevalidationScanResponse> {
  return apiFetch<RevalidationScanResponse>("/revalidation/scan", { method: "POST" });
}

export function listRevalidationCandidates(
  params: { status?: string } = {},
  options: { cache?: RequestCache } = {}
): Promise<RevalidationCandidateListResponse> {
  return apiFetch<RevalidationCandidateListResponse>("/revalidation", { searchParams: params, cache: options.cache });
}

export function getRevalidationCandidate(
  candidateId: string,
  options: { cache?: RequestCache } = {}
): Promise<RevalidationCandidateResponse> {
  return apiFetch<RevalidationCandidateResponse>(`/revalidation/${encodeURIComponent(candidateId)}`, {
    cache: options.cache,
  });
}

export function createRevalidationCandidate(request: CreateRevalidationCandidateRequest): Promise<RevalidationCandidateResponse> {
  return apiFetch<RevalidationCandidateResponse>("/revalidation", { method: "POST", body: request });
}

export function approveRevalidationCandidate(
  candidateId: string,
  request: RevalidationDecisionRequest
): Promise<RevalidationCandidateResponse> {
  return apiFetch<RevalidationCandidateResponse>(`/revalidation/${encodeURIComponent(candidateId)}/approve`, {
    method: "POST",
    body: request,
  });
}

export function dismissRevalidationCandidate(
  candidateId: string,
  request: RevalidationDecisionRequest
): Promise<RevalidationCandidateResponse> {
  return apiFetch<RevalidationCandidateResponse>(`/revalidation/${encodeURIComponent(candidateId)}/dismiss`, {
    method: "POST",
    body: request,
  });
}
