"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { FormField, Textarea } from "@/components/ui/Field";
import { studioApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";
import type { ExperimentVersionStatus } from "@/lib/api/types";

type Action = "submit-review" | "start-review" | "approve" | "reject" | "retire";

const ACTIONS_BY_STATUS: Record<ExperimentVersionStatus, { action: Action; label: string; variant: "primary" | "danger" }[]> = {
  draft: [{ action: "submit-review", label: "Submit for review", variant: "primary" }],
  ready_for_review: [{ action: "start-review", label: "Start review", variant: "primary" }],
  under_review: [
    { action: "approve", label: "Approve", variant: "primary" },
    { action: "reject", label: "Reject", variant: "danger" },
  ],
  approved: [{ action: "retire", label: "Retire", variant: "danger" }],
  rejected: [],
  retired: [],
};

const TRANSITIONS: Record<Action, (versionId: string, request: { reason?: string | null }) => Promise<unknown>> = {
  "submit-review": studioApi.submitVersionForReview,
  "start-review": studioApi.startVersionReview,
  approve: studioApi.approveVersion,
  reject: studioApi.rejectVersion,
  retire: studioApi.retireVersion,
};

export function ApprovalActionPanel({ versionId, status }: { versionId: string; status: ExperimentVersionStatus }) {
  const router = useRouter();
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);

  const actions = ACTIONS_BY_STATUS[status];
  if (actions.length === 0) {
    return <p className="text-sm text-text-muted">This version is {status} - no further transitions are available.</p>;
  }

  async function handle(action: Action) {
    setPending(action);
    setError(null);
    try {
      await TRANSITIONS[action](versionId, { reason: reason.trim() || null });
      router.refresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 403 && err.body?.error === "self_approval_forbidden") {
        setError("You created this version, so you cannot also approve it - a different reviewer must approve it.");
      } else {
        setError(err instanceof ApiError ? err.message : "Action failed.");
      }
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <FormField id="reason" label="Reason / comment" hint="Recorded on the approval history.">
        <Textarea id="reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
      </FormField>
      {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}
      <div className="flex gap-2">
        {actions.map((a) => (
          <Button key={a.action} variant={a.variant} onClick={() => handle(a.action)} disabled={pending !== null}>
            {pending === a.action ? "Working…" : a.label}
          </Button>
        ))}
      </div>
      <p className="text-xs text-text-muted">
        Approving only advances the workflow status - SafetyPolicy is still evaluated independently, every time a run
        is actually submitted. Approval never bypasses runtime safety checks, and you can never approve a version you
        created yourself.
      </p>
    </div>
  );
}
