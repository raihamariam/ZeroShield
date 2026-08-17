"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Field";

const CVE_PATTERN = /^CVE-\d{4}-\d{4,7}$/i;

/** Jumps straight to a known CVE's detail page. The vulnerabilities list endpoint has
 * no free-text/cve_id search param (only vendor/product substring and score/domain/KEV
 * filters, applied via the plain GET filter form on this page) - this is the honest
 * complement for "I already know the CVE ID I want". */
export function CveJumpForm() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = value.trim().toUpperCase();
    if (!CVE_PATTERN.test(trimmed)) {
      setError("Enter a full CVE ID, e.g. CVE-2024-12345");
      return;
    }
    setError(null);
    router.push(`/vulnerabilities/${trimmed}`);
  }

  return (
    <form onSubmit={handleSubmit} className="flex items-end gap-2" aria-label="Go to a specific CVE">
      <div className="flex flex-col gap-1.5">
        <label htmlFor="cve-jump" className="text-sm font-medium text-foreground">
          Go to CVE
        </label>
        <Input
          id="cve-jump"
          name="cve"
          placeholder="CVE-2024-12345"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          aria-describedby={error ? "cve-jump-error" : undefined}
          aria-invalid={error ? true : undefined}
          className="w-44"
        />
      </div>
      <Button type="submit" variant="secondary">
        Go
      </Button>
      {error ? (
        <p id="cve-jump-error" role="alert" className="text-xs font-medium text-danger">
          {error}
        </p>
      ) : null}
    </form>
  );
}
