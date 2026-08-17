import { apiFetch } from "./client";
import type {
  AuditEventListResponse,
  CreateUserRequest,
  LoginRequest,
  LoginResponse,
  UpdateUserActiveRequest,
  UpdateUserRoleRequest,
  UserListResponse,
  UserResponse,
} from "./types";

// V2 Phase 6: session-cookie auth. login()/logout() rely on the browser (or,
// server-side, apps/web/src/lib/api/client.ts's cookie-forwarding) actually
// storing/sending the httpOnly session cookie - neither function handles the
// token itself, it never exists in JS-reachable state.

export function login(request: LoginRequest): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/auth/login", { method: "POST", body: request });
}

export function logout(): Promise<void> {
  return apiFetch<void>("/auth/logout", { method: "POST" });
}

export function me(options: { cache?: RequestCache } = {}): Promise<UserResponse> {
  return apiFetch<UserResponse>("/auth/me", { cache: options.cache ?? "no-store" });
}

export function listUsers(options: { cache?: RequestCache } = {}): Promise<UserListResponse> {
  return apiFetch<UserListResponse>("/users", { cache: options.cache });
}

export function createUser(request: CreateUserRequest): Promise<UserResponse> {
  return apiFetch<UserResponse>("/users", { method: "POST", body: request });
}

export function updateUserRole(userId: string, request: UpdateUserRoleRequest): Promise<UserResponse> {
  return apiFetch<UserResponse>(`/users/${encodeURIComponent(userId)}/role`, { method: "PATCH", body: request });
}

export function updateUserActive(userId: string, request: UpdateUserActiveRequest): Promise<UserResponse> {
  return apiFetch<UserResponse>(`/users/${encodeURIComponent(userId)}/active`, { method: "PATCH", body: request });
}

export interface AuditEventListParams {
  action?: string;
  target_type?: string;
  target_id?: string;
  actor_user_id?: string;
  limit?: number;
  offset?: number;
  [key: string]: string | number | undefined;
}

export function listAuditEvents(
  params: AuditEventListParams = {},
  options: { cache?: RequestCache } = {}
): Promise<AuditEventListResponse> {
  return apiFetch<AuditEventListResponse>("/audit-events", { searchParams: params, cache: options.cache });
}
