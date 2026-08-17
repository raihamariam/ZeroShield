"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { FormField, Input, Textarea } from "@/components/ui/Field";
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

const TRANSITIONS: Record<Action, (versionId: string, request: { actor: string; reason?: string | null }) => Promise<unknown>> = {
  "submit-review": studioApi.submitVersionForReview,
  "start-review": studioApi.startVersionReview,
  approve: studioApi.approveVersion,
  reject: studioApi.rejectVersion,
  retire: studioApi.retireVersion,
};

export function ApprovalActionPanel({ versionId, status }: { versionId: string; status: ExperimentVersionStatus }) {
  const router = useRouter();
  const [actor, setActor] = useState(() => (typeof window !== "undefined" ? window.localStorage.getItem("zeroshield.createdBy") ?? "" : ""));
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);

  const actions = ACTIONS_BY_STATUS[status];
  if (actions.length === 0) {
    return <p className="text-sm text-text-muted">This version is {status} - no further transitions are available.</p>;
  }

  async function handle(action: Action) {
    if (!actor.trim()) {
      setError("Enter your name first.");
      return;
    }
    setPending(action);
    setError(null);
    try {
      window.localStorage.setItem("zeroshield.createdBy", actor.trim());
      await TRANSITIONS[action](versionId, { actor: actor.trim(), reason: reason.trim() || null });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Action failed.");
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <FormField id="actor" label="Your name" required className="max-w-xs">
        <Input id="actor" value={actor} onChange={(e) => setActor(e.target.value)} />
      </FormField>
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
        is actually submitted. Approval never bypasses runtime safety checks.
      </p>
    </div>
  );
}
