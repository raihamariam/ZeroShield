"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { FormField, Select } from "@/components/ui/Field";
import { analystApi, studioApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";
import type { AIAssessmentResponse, ValidationTemplateResponse } from "@/lib/api/types";
import { formatDateTime, formatPercent, titleCase } from "@/lib/utils/format";

type Action = "failure-pattern" | "mitigation-gap" | "similar" | "template-recommendation";

const ACTIONS: { action: Action; label: string; hint: string }[] = [
  { action: "failure-pattern", label: "Classify failure pattern", hint: "Which defensive failure pattern this CVE most resembles." },
  { action: "mitigation-gap", label: "Analyze mitigation gap", hint: "Gaps in the vendor's own mitigation guidance." },
  { action: "similar", label: "Summarise similarity", hint: "Narrates the deterministic correlation list below in plain language." },
  { action: "template-recommendation", label: "Recommend template", hint: "Suggests an existing, allow-listed validation template." },
];

/** Every AI action here is advisory only - it persists an AIAssessmentRecord
 * with reviewed=false and cannot approve, execute, or alter anything else.
 * See src/zeroshield/api/routes/analyst.py, which this panel is a thin
 * client-side mirror of. */
export function AnalystActionsPanel({
  cveId,
  domainPackId,
  initialAssessments,
}: {
  cveId: string;
  domainPackId: string | null;
  initialAssessments: AIAssessmentResponse[];
}) {
  const [assessments, setAssessments] = useState(initialAssessments);
  const [pending, setPending] = useState<Action | "experiment-draft" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [templates, setTemplates] = useState<ValidationTemplateResponse[] | null>(null);
  const [selectedTemplateId, setSelectedTemplateId] = useState("");

  function upsert(assessment: AIAssessmentResponse) {
    setAssessments((prev) => [assessment, ...prev.filter((a) => a.assessment_id !== assessment.assessment_id)]);
  }

  async function run(action: Action) {
    setPending(action);
    setError(null);
    try {
      const fn = {
        "failure-pattern": analystApi.classifyFailurePattern,
        "mitigation-gap": analystApi.analyzeMitigationGap,
        similar: analystApi.summariseSimilarity,
        "template-recommendation": analystApi.recommendTemplate,
      }[action];
      upsert(await fn(cveId));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "AI request failed.");
    } finally {
      setPending(null);
    }
  }

  async function loadTemplates() {
    if (!domainPackId || templates !== null) return;
    try {
      const result = await studioApi.listDomainPackTemplates(domainPackId);
      setTemplates(result.templates);
      setSelectedTemplateId(result.templates[0]?.template_id ?? "");
    } catch {
      setTemplates([]);
    }
  }

  async function draftProposal() {
    if (!domainPackId || !selectedTemplateId) return;
    setPending("experiment-draft");
    setError(null);
    try {
      upsert(await analystApi.draftExperimentProposal(cveId, { domain_pack_id: domainPackId, template_id: selectedTemplateId }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "AI request failed.");
    } finally {
      setPending(null);
    }
  }

  async function review(assessmentId: string) {
    const reviewedBy = typeof window !== "undefined" ? window.prompt("Your name, to record as the reviewer:") : null;
    if (!reviewedBy?.trim()) return;
    try {
      upsert(await analystApi.reviewAssessment(assessmentId, { reviewed_by: reviewedBy.trim() }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Review failed.");
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2">
        {ACTIONS.map((a) => (
          <Button key={a.action} variant="secondary" size="sm" onClick={() => run(a.action)} disabled={pending !== null} title={a.hint}>
            {pending === a.action ? "Working…" : a.label}
          </Button>
        ))}
      </div>

      {domainPackId ? (
        <div className="flex flex-wrap items-end gap-2 rounded-lg border border-border bg-surface-muted p-3">
          <FormField id="draft-template" label="Draft experiment proposal from template" className="min-w-56">
            <Select
              id="draft-template"
              value={selectedTemplateId}
              onFocus={loadTemplates}
              onChange={(e) => setSelectedTemplateId(e.target.value)}
            >
              {templates === null ? <option value="">Click to load templates…</option> : null}
              {templates?.length === 0 ? <option value="">No templates for this domain</option> : null}
              {templates?.map((t) => (
                <option key={`${t.template_id}:${t.version}`} value={t.template_id}>
                  {t.template_id} (v{t.version})
                </option>
              ))}
            </Select>
          </FormField>
          <Button variant="secondary" size="sm" onClick={draftProposal} disabled={pending !== null || !selectedTemplateId}>
            {pending === "experiment-draft" ? "Drafting…" : "Draft proposal"}
          </Button>
        </div>
      ) : (
        <p className="text-xs text-text-muted">
          Template recommendation and experiment-draft actions require a determined domain (VPN/Telecom) for this CVE.
        </p>
      )}

      {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}

      {assessments.length === 0 ? (
        <p className="text-sm text-text-muted">No AI assessments yet for this CVE - run one of the actions above.</p>
      ) : (
        <ul className="flex flex-col gap-3">
          {assessments.map((a) => (
            <AssessmentCard key={a.assessment_id} assessment={a} onReview={() => review(a.assessment_id)} />
          ))}
        </ul>
      )}
    </div>
  );
}

function AssessmentCard({ assessment, onReview }: { assessment: AIAssessmentResponse; onReview: () => void }) {
  const p = assessment.payload;
  return (
    <li className="rounded-lg border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Badge variant="accent">{titleCase(assessment.assessment_type)}</Badge>
          <span className="text-xs text-text-muted">Confidence {formatPercent(assessment.confidence, 0)}</span>
          <span className="text-xs text-text-muted">{formatDateTime(assessment.created_at)}</span>
        </div>
        {assessment.reviewed ? (
          <Badge variant="success">Reviewed by {assessment.reviewed_by}</Badge>
        ) : (
          <Button variant="ghost" size="sm" onClick={onReview}>
            Mark reviewed
          </Button>
        )}
      </div>
      <div className="mt-2 text-foreground">{renderPayload(assessment.assessment_type, p)}</div>
      {typeof p.rationale === "string" ? <p className="mt-2 text-xs text-text-muted italic">&ldquo;{p.rationale}&rdquo;</p> : null}
      <p className="mt-2 text-[11px] text-text-muted">
        Advisory only, from {String(p.provider ?? "unknown")} / {String(p.model ?? "unknown")} - never automatically acted on.
      </p>
    </li>
  );
}

function renderPayload(type: string, p: Record<string, unknown>) {
  switch (type) {
    case "failure_pattern":
      return <p>Failure pattern: <span className="font-medium">{String(p.failure_pattern || "(none identified)")}</span></p>;
    case "mitigation_gap":
      return (
        <ul className="list-disc space-y-1 pl-5">
          {(p.gaps as string[] | undefined)?.map((g, i) => <li key={i}>{g}</li>)}
        </ul>
      );
    case "similarity":
      return <p>Similar to: {(p.similar_cve_ids as string[] | undefined)?.join(", ") || "(none)"}</p>;
    case "template_recommendation":
      return (
        <p>
          Recommended template: <span className="font-medium">{String(p.template_id)}</span> (v{String(p.template_version)}) in{" "}
          {String(p.domain_pack_id)}
        </p>
      );
    case "experiment_draft":
      return (
        <div className="flex flex-col gap-1">
          <p className="font-medium">{String(p.title)}</p>
          <p><span className="text-text-muted">Research question:</span> {String(p.research_question)}</p>
          <p><span className="text-text-muted">Hypothesis:</span> {String(p.hypothesis)}</p>
        </div>
      );
    default:
      return <pre className="overflow-x-auto text-xs">{JSON.stringify(p, null, 2)}</pre>;
  }
}
