"use client";

import { useEffect } from "react";
import { ErrorState } from "@/components/ui";
import { Button } from "@/components/ui/Button";

/** Root error boundary - catches render-time errors that a page didn't already turn
 * into an inline ErrorState (API fetch failures are handled per-section instead, see
 * apps/web/src/app/page.tsx). This is the last-resort net for anything else. */
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="flex flex-col gap-4">
      <ErrorState error={error} />
      <div>
        <Button variant="secondary" onClick={reset}>
          Try again
        </Button>
      </div>
    </div>
  );
}
