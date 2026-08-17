import { apiFetch, apiUrl } from "./client";
import type { JobListResponse, JobStatus, JobStatusResponse } from "./types";

export function listJobs(
  params: { status?: JobStatus; limit?: number } = {},
  options: { cache?: RequestCache } = {}
): Promise<JobListResponse> {
  return apiFetch<JobListResponse>("/jobs", {
    searchParams: { status: params.status, limit: params.limit },
    cache: options.cache,
  });
}

export function getJob(jobId: string, options: { cache?: RequestCache } = {}): Promise<JobStatusResponse> {
  return apiFetch<JobStatusResponse>(`/jobs/${encodeURIComponent(jobId)}`, { cache: options.cache });
}

/** Browser-only: same-origin SSE URL for GET /jobs/{job_id}/events, to be handed to
 * `new EventSource(...)`. Never call from a Server Component. */
export function jobEventsUrl(jobId: string): string {
  return apiUrl(`/jobs/${encodeURIComponent(jobId)}/events`);
}
