"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { revalidationApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

export function RevalidationScanButton() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function scan() {
    setPending(true);
    setMessage(null);
    try {
      const result = await revalidationApi.scanForRevalidation();
      setMessage(
        result.candidates_created.length === 0
          ? `Scanned ${result.controls_scanned} control(s) - no new triggers.`
          : `Scanned ${result.controls_scanned} control(s) - ${result.candidates_created.length} new candidate(s) raised.`
      );
      router.refresh();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : "Scan failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div>
      <Button variant="primary" onClick={scan} disabled={pending}>
        {pending ? "Scanning…" : "Scan for revalidation triggers"}
      </Button>
      {message ? <p className="mt-1.5 text-xs text-text-muted">{message}</p> : null}
    </div>
  );
}
