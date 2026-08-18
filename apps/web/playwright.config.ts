import { defineConfig, devices } from "@playwright/test";

/**
 * Two tiers of spec live under e2e/:
 *  - e2e/smoke/  - navigation, empty/error states, 404s. Needs no backend, and every
 *    project run executes these (they're what CI/local `npm run test:e2e` verifies).
 *  - e2e/workflows/ - the full CVE -> Experiment Studio -> Approve -> Run -> Verdict ->
 *    Evidence journey from the Phase 4 brief. These need a live backend (docker compose
 *    up) with seeded data and only run when RUN_E2E_LIVE=1 is set - see e2e/README.md.
 */
const runLive = process.env.RUN_E2E_LIVE === "1";

export default defineConfig({
  testDir: "./e2e",
  testMatch: runLive ? ["smoke/**/*.spec.ts", "workflows/**/*.spec.ts"] : ["smoke/**/*.spec.ts"],
  // Playwright's own default per-test timeout is 30s - fine for smoke/, but workflows/
  // specs explicitly wait up to 120s for a run to complete and 60s for a sync to finish
  // (their own coded {timeout: 120_000}/.toPass({timeout: 60_000}) budgets), which the
  // 30s default was silently truncating before those budgets ever got exercised (a real,
  // observed failure mode: full-lifecycle.spec.ts and three governance-acceptance.spec.ts
  // specs all failed with "Test timeout of 30000ms exceeded" at unrelated points, not at
  // an assertion). Only raised for the live tier - smoke/ keeps Playwright's real default.
  timeout: runLive ? 180_000 : undefined,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: "list",
  use: {
    baseURL: "http://localhost:3100",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npx next dev -p 3100",
    url: "http://localhost:3100",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
