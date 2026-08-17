import type { ApiErrorBody } from "./types";

/**
 * The one place that knows how to reach the ZeroShield FastAPI backend. The UI
 * consumes FastAPI exclusively - never Postgres/MinIO/RabbitMQ/Python directly.
 *
 * - Server Components / Route Handlers run in Node and call the backend directly
 *   via API_BASE_URL (server-only env var, not exposed to the browser).
 * - Client Components call the same-origin "/api/*" path, which next.config.ts
 *   rewrites to the backend - this avoids ever needing FastAPI to grant CORS to
 *   the Next.js origin, and keeps the backend's real address out of client bundles.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody | null;

  constructor(status: number, body: ApiErrorBody | null, message?: string) {
    super(message ?? body?.detail ?? `ZeroShield API request failed (HTTP ${status})`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }

  /** True when the backend itself couldn't be reached at all (network/DNS/refused). */
  get isUnreachable(): boolean {
    return this.status === 0;
  }
}

function resolveBaseUrl(): string {
  if (typeof window === "undefined") {
    return process.env.API_BASE_URL ?? "http://localhost:8000";
  }
  return "/api";
}

export type QueryParams = Record<string, string | number | boolean | undefined | null>;

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  searchParams?: QueryParams;
  signal?: AbortSignal;
  /** Forwarded to fetch()'s cache option. Defaults to Next's own per-request default
   * (uncached), which is what a live operational dashboard wants - see apps/web/README.md. */
  cache?: RequestCache;
}

function buildUrl(path: string, searchParams?: QueryParams): string {
  const query = new URLSearchParams();
  if (searchParams) {
    for (const [key, value] of Object.entries(searchParams)) {
      if (value !== undefined && value !== null && value !== "") {
        query.set(key, String(value));
      }
    }
  }
  const qs = query.toString();
  return `${resolveBaseUrl()}${path}${qs ? `?${qs}` : ""}`;
}

async function parseErrorBody(response: Response): Promise<ApiErrorBody | null> {
  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    return null;
  }
  if (raw && typeof raw === "object" && "detail" in raw) {
    const detail = (raw as { detail: unknown }).detail;
    if (detail && typeof detail === "object" && "error" in detail && "detail" in detail) {
      return detail as ApiErrorBody;
    }
    if (typeof detail === "string") {
      return { error: "request_error", detail };
    }
    // FastAPI's own 422 validation-error shape: detail is a list of {loc, msg, type}.
    return { error: "validation_error", detail: JSON.stringify(detail) };
  }
  return null;
}

/** Issues a request and decodes the JSON response body as T. Throws ApiError on any
 * non-2xx response or network failure - callers never need to check response.ok. */
export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, searchParams, signal, cache } = options;
  const url = buildUrl(path, searchParams);

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
      cache,
    });
  } catch {
    throw new ApiError(0, null, "Could not reach the ZeroShield API. Is the backend running?");
  }

  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorBody(response));
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

/** Like apiFetch, but returns the raw Response for binary/streamed bodies (e.g. the
 * evidence bundle zip download) instead of decoding JSON. */
export async function apiFetchRaw(path: string, options: RequestOptions = {}): Promise<Response> {
  const { method = "GET", searchParams, signal, cache } = options;
  const url = buildUrl(path, searchParams);

  let response: Response;
  try {
    response = await fetch(url, { method, signal, cache });
  } catch {
    throw new ApiError(0, null, "Could not reach the ZeroShield API. Is the backend running?");
  }
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorBody(response));
  }
  return response;
}

/** Same-origin path for browser-only APIs that need a plain URL string rather than a
 * fetch() call - currently just EventSource for the live-run SSE stream. */
export function apiUrl(path: string, searchParams?: QueryParams): string {
  return buildUrl(path, searchParams);
}
