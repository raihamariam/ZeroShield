"use client";

import { useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Sidebar } from "./Sidebar";
import { UserMenu } from "./UserMenu";
import type { UserResponse } from "@/lib/api/types";

export function AppShell({ children, currentUser }: { children: ReactNode; currentUser: UserResponse | null }) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const pathname = usePathname();

  // /login renders its own centred, chrome-free layout - showing the nav/
  // sidebar there would both look wrong and imply the visitor is already
  // signed in.
  if (pathname === "/login") {
    return <div className="min-h-full">{children}</div>;
  }

  return (
    <div className="flex min-h-full flex-col">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-foreground"
      >
        Skip to main content
      </a>

      <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-surface px-4">
        <button
          type="button"
          onClick={() => setMobileNavOpen((open) => !open)}
          aria-expanded={mobileNavOpen}
          aria-controls="mobile-nav-drawer"
          className="rounded-lg border border-border p-2 md:hidden"
        >
          <span className="sr-only">{mobileNavOpen ? "Close navigation" : "Open navigation"}</span>
          <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <Link href="/" className="text-sm font-semibold text-foreground">
          ZeroShield <span className="font-normal text-text-muted">Continuous Mitigation Assurance</span>
        </Link>
        <div className="ml-auto">
          <UserMenu currentUser={currentUser} />
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <aside className="hidden w-64 shrink-0 border-r border-border bg-surface md:block">
          <Sidebar />
        </aside>

        {mobileNavOpen ? (
          <div className="fixed inset-0 z-40 md:hidden">
            <button
              type="button"
              aria-label="Close navigation overlay"
              className="absolute inset-0 bg-black/40"
              onClick={() => setMobileNavOpen(false)}
            />
            <div
              id="mobile-nav-drawer"
              className="absolute inset-y-0 left-0 w-72 max-w-[85vw] overflow-y-auto border-r border-border bg-surface shadow-xl"
            >
              <Sidebar />
            </div>
          </div>
        ) : null}

        <main id="main-content" className="min-w-0 flex-1 p-4 sm:p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
