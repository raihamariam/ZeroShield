import { apiFetch } from "./client";
import type {
  AIAssessmentResponse,
  ControlEffectivenessResponse,
  ControlListResponse,
  ControlResponse,
  ControlVersionListResponse,
} from "./types";

// -- Defensive controls & effectiveness (V2 Phase 5, Steps 8/9/10).

export function listControls(options: { cache?: RequestCache } = {}): Promise<ControlListResponse> {
  return apiFetch<ControlListResponse>("/controls", { cache: options.cache });
}

export function getControl(controlId: string, options: { cache?: RequestCache } = {}): Promise<ControlResponse> {
  return apiFetch<ControlResponse>(`/controls/${encodeURIComponent(controlId)}`, { cache: options.cache });
}

export function listControlVersions(
  controlId: string,
  options: { cache?: RequestCache } = {}
): Promise<ControlVersionListResponse> {
  return apiFetch<ControlVersionListResponse>(`/controls/${encodeURIComponent(controlId)}/versions`, {
    cache: options.cache,
  });
}

export function getControlEffectiveness(
  controlId: string,
  options: { cache?: RequestCache } = {}
): Promise<ControlEffectivenessResponse> {
  return apiFetch<ControlEffectivenessResponse>(`/controls/${encodeURIComponent(controlId)}/effectiveness`, {
    cache: options.cache,
  });
}

/** Step 10: "AI may explain a regression, not independently declare it." Only
 * succeeds if getControlEffectiveness's own deterministic regression check has
 * already found one - see src/zeroshield/api/routes/controls.py. */
export function explainRegression(controlId: string): Promise<AIAssessmentResponse> {
  return apiFetch<AIAssessmentResponse>(`/controls/${encodeURIComponent(controlId)}/regression/explain`, {
    method: "POST",
  });
}
