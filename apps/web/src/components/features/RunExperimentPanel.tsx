"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { ApiError } from "@/lib/api/client";
import { experimentsApi } from "@/lib/api";
import type { ExecutionContext, ValidationResponse } from "@/lib/api/types";

const CONTEXTS: { value: ExecutionContext; label: string; hint: string }[] = [
  {
    value: "experiment_run",
    label: "Experiment run",
    hint: "The strict gate a real run uses - requires the experiment to be approved.",
  },
  {
    value: "local_unit_test",
    label: "Local unit test",
    hint: "Draft-only local demonstration carve-out - relaxes only the approval-status check.",
  },
];

/** Lets a reviewer/operator submit a real async run for an already-materialised experiment
 * (POST /experiments/{id}/runs), then hands off to the live SSE run view. SafetyPolicy is
 * evaluated by the worker regardless of what this panel shows - the pre-flight check here
 * (POST /experiments/{id}/validate) is advisory UI feedback only, never a bypass. */
export function RunExperimentPanel({ experimentId }: { experimentId: string }) {
  const router = useRouter();
  const [context, setContext] = useState<ExecutionContext>("experiment_run");
  const [result, setResult] = useState<{ context: ExecutionContext; validation: ValidationResponse } | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    experimentsApi
      .validateExperiment(experimentId, context)
      .then((validation) => {
        if (!cancelled) setResult({ context, validation });
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Could not check safety status.");
      });
    return () => {
      cancelled = true;
    };
  }, [experimentId, context]);

  const checking = result?.context !== context;
  const validation = result?.context === context ? result.validation : null;

  async function handleSubmit() {
    setSubmitting(true);
    setError(null);
    try {
      const job = await experimentsApi.submitExperimentRun(experimentId, context);
      router.push(`/runs/${job.job_id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to submit run.");
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium text-foreground">Execution context</legend>
        {CONTEXTS.map((c) => (
          <label key={c.value} className="flex items-start gap-2 text-sm">
            <input
              type="radio"
              name="execution_context"
              value={c.value}
              checked={context === c.value}
              onChange={() => setContext(c.value)}
              className="mt-0.5 h-4 w-4 border-border text-accent"
            />
            <span>
              <span className="font-medium text-foreground">{c.label}</span>
              <span className="block text-xs text-text-muted">{c.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <div aria-live="polite">
        {checking ? (
          <p className="text-sm text-text-muted">Checking safety status…</p>
        ) : validation ? (
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              {validation.overall_valid ? (
                <Badge variant="success">Safety policy: PASSED</Badge>
              ) : (
                <Badge variant="danger">Safety policy: DENIED</Badge>
              )}
              {!validation.dataset_available ? <Badge variant="warning">Dataset not found</Badge> : null}
            </div>
            {validation.safety_reasons.length > 0 ? (
              <ul className="list-disc space-y-0.5 pl-5 text-xs text-text-muted">
                {validation.safety_reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
      </div>

      {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}

      <div>
        <Button
          onClick={handleSubmit}
          disabled={submitting || checking || !validation?.overall_valid}
          variant="primary"
        >
          {submitting ? "Submitting…" : "Submit run"}
        </Button>
      </div>
      <p className="text-xs text-text-muted">
        Submitting queues the run - SafetyPolicy is evaluated again by the worker itself when the run actually
        executes, so this check is a preview, not a guarantee.
      </p>
    </div>
  );
}
