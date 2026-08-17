"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { FormField, Input } from "@/components/ui/Field";
import { authApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await authApi.login({ username, password });
      const next = searchParams.get("next");
      router.push(next && next.startsWith("/") ? next : "/");
      router.refresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 423) {
        setError("Too many failed attempts - this account is temporarily locked. Try again later.");
      } else if (err instanceof ApiError && err.status === 403) {
        setError("This account has been deactivated. Contact an administrator.");
      } else if (err instanceof ApiError) {
        setError(err.body?.detail ?? "Invalid username or password.");
      } else {
        setError("Could not reach the ZeroShield API. Is the backend running?");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <div className="w-full max-w-sm rounded-xl border border-border bg-surface p-6 shadow-sm">
        <h1 className="text-lg font-semibold text-foreground">ZeroShield</h1>
        <p className="mt-1 text-sm text-text-muted">Sign in to continue.</p>

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
          <FormField id="username" label="Username" required>
            <Input
              id="username"
              name="username"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </FormField>
          <FormField id="password" label="Password" required>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </FormField>
          {error ? (
            <p role="alert" className="text-sm font-medium text-danger">
              {error}
            </p>
          ) : null}
          <Button type="submit" variant="primary" disabled={submitting || !username.trim() || !password}>
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <p className="mt-4 text-xs text-text-muted">
          No account? Ask an administrator to create one via <code>zeroshield create-admin</code> or the Users page.
        </p>
      </div>
    </div>
  );
}
