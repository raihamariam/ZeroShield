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
