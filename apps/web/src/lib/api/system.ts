import { apiFetch } from "./client";
import type { HealthResponse, SystemStatusResponse } from "./types";

export function getHealth(options: { cache?: RequestCache } = {}): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/health", { cache: options.cache });
}

export function getSystemStatus(options: { cache?: RequestCache } = {}): Promise<SystemStatusResponse> {
  return apiFetch<SystemStatusResponse>("/system/status", { cache: options.cache });
}
