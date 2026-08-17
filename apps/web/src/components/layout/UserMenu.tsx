"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { authApi } from "@/lib/api";
import type { UserResponse } from "@/lib/api/types";
import { titleCase } from "@/lib/utils/format";

/** currentUser is null whenever the server-side GET /auth/me RootLayout does
 * failed (no/expired session) - proxy.ts should already have redirected to
 * /login before this ever renders on a real page, so null here is a defensive
 * fallback, not the primary gate (see proxy.ts's own docstring). */
export function UserMenu({ currentUser }: { currentUser: UserResponse | null }) {
  const router = useRouter();
  const [loggingOut, setLoggingOut] = useState(false);

  if (!currentUser) {
    return (
      <Button href="/login" variant="secondary" size="sm">
        Sign in
      </Button>
    );
  }

  async function handleLogout() {
    setLoggingOut(true);
    try {
      await authApi.logout();
    } finally {
      router.push("/login");
      router.refresh();
    }
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-foreground">{currentUser.username}</span>
      <Badge variant="neutral">{titleCase(currentUser.role)}</Badge>
      <Button variant="ghost" size="sm" onClick={handleLogout} disabled={loggingOut}>
        {loggingOut ? "Signing out…" : "Sign out"}
      </Button>
    </div>
  );
}
