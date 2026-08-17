"use client";

import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { controlsApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

/** Step 10: "AI may explain a regression, not independently declare it." Only
 * ever callable once GET .../effectiveness has already deterministically found
 * one (see the parent page - this button only renders when that's true). */
export function RegressionExplainButton({ controlId }: { controlId: string }) {
  const [explanation, setExplanation] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function explain() {
    setPending(true);
    setError(null);
    try {
      const assessment = await controlsApi.explainRegression(controlId);
      setExplanation(String(assessment.payload.explanation ?? ""));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "AI request failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="mt-2">
      {explanation ? (
        <p className="rounded-lg border border-border bg-surface p-3 text-sm text-foreground">
          <span className="font-medium">AI explanation (advisory): </span>
          {explanation}
        </p>
      ) : (
        <Button variant="secondary" size="sm" onClick={explain} disabled={pending}>
          {pending ? "Asking the analyst…" : "Explain with AI"}
        </Button>
      )}
      {error ? <p className="mt-1 text-xs font-medium text-danger">{error}</p> : null}
    </div>
  );
}
