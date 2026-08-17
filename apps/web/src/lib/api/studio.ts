import { apiFetch } from "./client";
import type {
  ApprovalActionRequest,
  ApprovalDecisionResponse,
  CreateExperimentVersionRequest,
  DomainPackListResponse,
  EditExperimentVersionRequest,
  ExperimentVersionListResponse,
  ExperimentVersionResponse,
  ExperimentVersionStatus,
  GenerateDatasetRequest,
  GenerateDatasetResponse,
  JobSubmittedResponse,
  ValidationTemplateListResponse,
  ValidationTemplateResponse,
} from "./types";

export function listDomainPacks(options: { cache?: RequestCache } = {}): Promise<DomainPackListResponse> {
  return apiFetch<DomainPackListResponse>("/domain-packs", { cache: options.cache });
}

export function listDomainPackTemplates(
  packId: string,
  options: { cache?: RequestCache } = {}
): Promise<ValidationTemplateListResponse> {
  return apiFetch<ValidationTemplateListResponse>(`/domain-packs/${encodeURIComponent(packId)}/templates`, {
    cache: options.cache,
  });
}

export function getTemplate(
  templateId: string,
  version: string,
  options: { cache?: RequestCache } = {}
): Promise<ValidationTemplateResponse> {
  return apiFetch<ValidationTemplateResponse>(
    `/templates/${encodeURIComponent(templateId)}/${encodeURIComponent(version)}`,
    { cache: options.cache }
  );
}

export function generateDataset(request: GenerateDatasetRequest): Promise<GenerateDatasetResponse> {
  return apiFetch<GenerateDatasetResponse>("/datasets/generate", { method: "POST", body: request });
}

export function createExperimentVersion(
  request: CreateExperimentVersionRequest
): Promise<ExperimentVersionResponse> {
  return apiFetch<ExperimentVersionResponse>("/experiment-versions", { method: "POST", body: request });
}

export function editExperimentVersion(
  versionId: string,
  request: EditExperimentVersionRequest
): Promise<ExperimentVersionResponse> {
  return apiFetch<ExperimentVersionResponse>(`/experiment-versions/${encodeURIComponent(versionId)}`, {
    method: "PATCH",
    body: request,
  });
}

export function getExperimentVersion(
  versionId: string,
  options: { cache?: RequestCache } = {}
): Promise<ExperimentVersionResponse> {
  return apiFetch<ExperimentVersionResponse>(`/experiment-versions/${encodeURIComponent(versionId)}`, {
    cache: options.cache,
  });
}

export function listExperimentVersions(
  params: { experiment_id?: string; status?: ExperimentVersionStatus } = {},
  options: { cache?: RequestCache } = {}
): Promise<ExperimentVersionListResponse> {
  return apiFetch<ExperimentVersionListResponse>("/experiment-versions", {
    searchParams: params,
    cache: options.cache,
  });
}

export function getApprovalHistory(
  versionId: string,
  options: { cache?: RequestCache } = {}
): Promise<ApprovalDecisionResponse[]> {
  return apiFetch<ApprovalDecisionResponse[]>(`/experiment-versions/${encodeURIComponent(versionId)}/approvals`, {
    cache: options.cache,
  });
}

function transition(
  versionId: string,
  action: "submit-review" | "start-review" | "approve" | "reject" | "retire",
  request: ApprovalActionRequest
): Promise<ExperimentVersionResponse> {
  return apiFetch<ExperimentVersionResponse>(
    `/experiment-versions/${encodeURIComponent(versionId)}/${action}`,
    { method: "POST", body: request }
  );
}

export const submitVersionForReview = (versionId: string, request: ApprovalActionRequest) =>
  transition(versionId, "submit-review", request);

export const startVersionReview = (versionId: string, request: ApprovalActionRequest) =>
  transition(versionId, "start-review", request);

export const approveVersion = (versionId: string, request: ApprovalActionRequest) =>
  transition(versionId, "approve", request);

export const rejectVersion = (versionId: string, request: ApprovalActionRequest) =>
  transition(versionId, "reject", request);

export const retireVersion = (versionId: string, request: ApprovalActionRequest) =>
  transition(versionId, "retire", request);

export function submitExperimentVersionRun(versionId: string): Promise<JobSubmittedResponse> {
  return apiFetch<JobSubmittedResponse>(`/experiment-versions/${encodeURIComponent(versionId)}/runs`, {
    method: "POST",
  });
}
