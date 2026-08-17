import { apiFetch } from "./client";
import type {
  PriorityQueueResponse,
  SourcesResponse,
  SupportStatus,
  SyncListResponse,
  SyncStatusResponse,
  SyncSubmittedResponse,
  VulnerabilityDetailResponse,
  VulnerabilityHistoryResponse,
  VulnerabilityListResponse,
} from "./types";

export interface VulnerabilityListParams {
  domain?: string;
  kev?: boolean;
  cvss_gte?: number;
  epss_gte?: number;
  vendor?: string;
  product?: string;
  limit?: number;
  offset?: number;
  [key: string]: string | number | boolean | undefined;
}

export function listVulnerabilities(
  params: VulnerabilityListParams = {},
  options: { cache?: RequestCache } = {}
): Promise<VulnerabilityListResponse> {
  return apiFetch<VulnerabilityListResponse>("/vulnerabilities", {
    searchParams: params,
    cache: options.cache,
  });
}

export function getVulnerability(
  cveId: string,
  options: { cache?: RequestCache } = {}
): Promise<VulnerabilityDetailResponse> {
  return apiFetch<VulnerabilityDetailResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}`, {
    cache: options.cache,
  });
}

export function getVulnerabilityHistory(
  cveId: string,
  options: { cache?: RequestCache } = {}
): Promise<VulnerabilityHistoryResponse> {
  return apiFetch<VulnerabilityHistoryResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/history`, {
    cache: options.cache,
  });
}

export interface PriorityQueueParams {
  domain?: string;
  support_status?: SupportStatus;
  priority_gte?: number;
  limit?: number;
  offset?: number;
  [key: string]: string | number | boolean | undefined;
}

export function getPriorityQueue(
  params: PriorityQueueParams = {},
  options: { cache?: RequestCache } = {}
): Promise<PriorityQueueResponse> {
  return apiFetch<PriorityQueueResponse>("/priority-queue", { searchParams: params, cache: options.cache });
}

export function listSources(options: { cache?: RequestCache } = {}): Promise<SourcesResponse> {
  return apiFetch<SourcesResponse>("/sources", { cache: options.cache });
}

export function listIntegrations(options: { cache?: RequestCache } = {}): Promise<SourcesResponse> {
  return apiFetch<SourcesResponse>("/integrations", { cache: options.cache });
}

export function submitSync(source: string, since?: string): Promise<SyncSubmittedResponse> {
  return apiFetch<SyncSubmittedResponse>("/intelligence/sync", {
    method: "POST",
    body: { source, since: since ?? null },
  });
}

export function listSyncs(
  params: { limit?: number; offset?: number } = {},
  options: { cache?: RequestCache } = {}
): Promise<SyncListResponse> {
  return apiFetch<SyncListResponse>("/intelligence/syncs", { searchParams: params, cache: options.cache });
}

export function getSync(syncId: string, options: { cache?: RequestCache } = {}): Promise<SyncStatusResponse> {
  return apiFetch<SyncStatusResponse>(`/intelligence/syncs/${encodeURIComponent(syncId)}`, {
    cache: options.cache,
  });
}
