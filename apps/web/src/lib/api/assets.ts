import { apiFetch } from "./client";
import type { AffectedAssetListResponse, AssetListResponse, AssetResponse, CreateAssetRequest, UpdateAssetRequest } from "./types";

// -- Asset inventory (V2 Phase 5, Step 7) - deliberately small, never a CMDB.

export interface AssetListParams {
  active?: boolean;
  vendor?: string;
  [key: string]: string | number | boolean | undefined;
}

export function listAssets(
  params: AssetListParams = {},
  options: { cache?: RequestCache } = {}
): Promise<AssetListResponse> {
  return apiFetch<AssetListResponse>("/assets", { searchParams: params, cache: options.cache });
}

export function getAsset(assetId: string, options: { cache?: RequestCache } = {}): Promise<AssetResponse> {
  return apiFetch<AssetResponse>(`/assets/${encodeURIComponent(assetId)}`, { cache: options.cache });
}

export function createAsset(request: CreateAssetRequest): Promise<AssetResponse> {
  return apiFetch<AssetResponse>("/assets", { method: "POST", body: request });
}

export function updateAsset(assetId: string, request: UpdateAssetRequest): Promise<AssetResponse> {
  return apiFetch<AssetResponse>(`/assets/${encodeURIComponent(assetId)}`, { method: "PATCH", body: request });
}

export function getAffectedAssets(
  cveId: string,
  options: { cache?: RequestCache } = {}
): Promise<AffectedAssetListResponse> {
  return apiFetch<AffectedAssetListResponse>(`/vulnerabilities/${encodeURIComponent(cveId)}/affected-assets`, {
    cache: options.cache,
  });
}
