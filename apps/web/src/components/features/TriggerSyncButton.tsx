"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { intelligenceApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

export function TriggerSyncButton({ source }: { source: string }) {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function handleClick() {
    setSubmitting(true);
    setMessage(null);
    try {
      const result = await intelligenceApi.submitSync(source);
      setMessage(`Queued: ${result.sync_id}`);
      router.refresh();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : "Failed to queue sync.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <Button variant="secondary" size="sm" onClick={handleClick} disabled={submitting}>
        {submitting ? "Queuing…" : "Trigger sync"}
      </Button>
      {message ? <p className="mt-1.5 text-xs text-text-muted">{message}</p> : null}
    </div>
  );
}
