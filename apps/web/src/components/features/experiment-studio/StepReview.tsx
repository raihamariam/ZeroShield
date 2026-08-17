"use client";

import { useState } from "react";
import Link from "next/link";
import { Badge } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { studioApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";
import type { CreateExperimentVersionRequest, ExperimentVersionResponse } from "@/lib/api/types";
import { cveRowToRequest } from "@/lib/experimentStudio";
import type { StepProps } from "./types";

function buildRequest(state: StepProps["state"]): CreateExperimentVersionRequest {
  const datasetConfig = state.datasetJsonMode
    ? (() => {
        try {
          return JSON.parse(state.datasetJsonText || "{}");
        } catch {
          return {};
        }
      })()
    : state.datasetConfig;

  return {
    experiment_id: state.experimentId,
    title: state.title.trim(),
    description: state.description.trim(),
    related_cves: state.cves.map((row) => cveRowToRequest(row, state.domain!)),
    domain_pack_id: state.domainPackId,
    template_id: state.templateId,
    template_version: state.templateVersion,
    dataset_config: datasetConfig,
    seed: state.seed,
    failure_pattern: state.failurePattern,
    root_cause: state.rootCause,
    vendor_mitigation: state.vendorMitigation.trim(),
    mitigation_gap: state.mitigationGap.trim(),
    research_question: state.researchQuestion.trim(),
    hypothesis: state.hypothesis.trim(),
    metrics_to_collect: state.metricsSelected,
  };
}

export function StepReview({ state }: StepProps) {
  const [showJson, setShowJson] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<ExperimentVersionResponse | null>(null);
  const [submittedForReview, setSubmittedForReview] = useState(false);

  const request = buildRequest(state);
  const template = state.templates.find((t) => t.template_id === state.templateId);

  async function handleSaveDraft() {
    setSubmitting(true);
    setError(null);
    try {
      const version = await studioApi.createExperimentVersion(request);
      setCreated(version);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save draft.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSubmitForReview() {
    if (!created) return;
    setSubmitting(true);
    setError(null);
    try {
      await studioApi.submitVersionForReview(created.version_id, {});
      setSubmittedForReview(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to submit for review.");
    } finally {
      setSubmitting(false);
    }
  }

  if (created) {
    return (
      <div className="flex flex-col gap-4">
        <div className="rounded-xl border border-success-bg bg-success-bg p-4">
          <p className="font-medium text-success">
            Draft saved: {created.experiment_id} v{created.version_number}
          </p>
          <p className="mt-1 text-sm text-foreground">
            {submittedForReview ? "Submitted for review." : "It's a draft - nothing runs or gets approved until you submit it for review."}
          </p>
        </div>
        {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}
        <div className="flex gap-3">
          {!submittedForReview ? (
            <Button onClick={handleSubmitForReview} disabled={submitting} variant="primary">
              {submitting ? "Submitting…" : "Submit for review"}
            </Button>
          ) : null}
          <Link href={`/approvals/${created.version_id}`} className="inline-flex items-center rounded-lg border border-border px-3.5 py-2 text-sm font-medium hover:bg-surface-muted">
            View version
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <ReviewField label="Experiment" value={`${request.experiment_id} — ${request.title}`} />
        <ReviewField label="Domain pack / template" value={`${request.domain_pack_id} / ${request.template_id} v${request.template_version}`} />
        <ReviewField label="Related CVEs" value={request.related_cves.map((c) => c.cve_id).join(", ")} />
        <ReviewField label="Safety level" value={template?.safety_level ?? "—"} />
        <ReviewField label="Seed" value={String(request.seed)} />
        <ReviewField label="Failure pattern" value={request.failure_pattern} />
        <ReviewField label="Metrics" value={request.metrics_to_collect?.join(", ") ?? "—"} />
      </div>

      <div>
        <button type="button" onClick={() => setShowJson((v) => !v)} className="text-xs font-medium text-accent hover:underline">
          {showJson ? "Hide" : "Show"} raw request JSON (advanced)
        </button>
        {showJson ? (
          <pre className="mt-2 max-h-96 overflow-auto rounded-lg border border-border bg-surface-muted p-3 text-xs">
            {JSON.stringify(request, null, 2)}
          </pre>
        ) : null}
      </div>

      {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}

      <div>
        <Button onClick={handleSaveDraft} disabled={submitting} variant="primary">
          {submitting ? "Saving…" : "Save draft"}
        </Button>
        <p className="mt-2 text-xs text-text-muted">
          Saves as <Badge variant="neutral">draft</Badge> - review and submit for approval on the next screen.
        </p>
      </div>
    </div>
  );
}

function ReviewField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <p className="mt-0.5 text-sm text-foreground">{value}</p>
    </div>
  );
}
