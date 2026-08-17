"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { analystApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

export function AssessmentReviewButton({ assessmentId }: { assessmentId: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function review() {
    const reviewedBy = typeof window !== "undefined" ? window.prompt("Your name, to record as the reviewer:") : null;
    if (!reviewedBy?.trim()) return;
    setPending(true);
    setError(null);
    try {
      await analystApi.reviewAssessment(assessmentId, { reviewed_by: reviewedBy.trim() });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Review failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div>
      <Button variant="ghost" size="sm" onClick={review} disabled={pending}>
        {pending ? "Saving…" : "Mark reviewed"}
      </Button>
      {error ? <p className="text-xs font-medium text-danger">{error}</p> : null}
    </div>
  );
}
