"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { revalidationApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

/** Only ever changes a RevalidationCandidate's status - approving here never
 * queues or executes a run. The actual run is a separate, ordinary submission
 * through Experiments/Experiment Studio (Step 11). */
export function RevalidationDecisionButtons({ candidateId }: { candidateId: string }) {
  const router = useRouter();
  const [pending, setPending] = useState<"approve" | "dismiss" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function decide(action: "approve" | "dismiss") {
    setPending(action);
    setError(null);
    try {
      const fn = action === "approve" ? revalidationApi.approveRevalidationCandidate : revalidationApi.dismissRevalidationCandidate;
      await fn(candidateId, {});
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Action failed.");
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Button variant="primary" size="sm" onClick={() => decide("approve")} disabled={pending !== null}>
        {pending === "approve" ? "Approving…" : "Approve"}
      </Button>
      <Button variant="ghost" size="sm" onClick={() => decide("dismiss")} disabled={pending !== null}>
        {pending === "dismiss" ? "Dismissing…" : "Dismiss"}
      </Button>
      {error ? <span className="text-xs font-medium text-danger">{error}</span> : null}
    </div>
  );
}
