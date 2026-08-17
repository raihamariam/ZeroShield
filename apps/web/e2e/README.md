# E2E tests

Two tiers, gated in `playwright.config.ts`:

- **`smoke/`** - navigation, empty/error states, 404s, accessibility basics. Needs no
  backend and runs on every `npm run test:e2e`. Since V2 Phase 6 added session-cookie
  auth (`src/proxy.ts`), every spec in this tier calls `injectFakeSessionCookie()` from
  `e2e/fixtures.ts` in a `beforeEach` - `proxy.ts` only checks *presence* of the session
  cookie, never validity (real validation is per-request, server-side), so this is enough
  to get back past the login redirect without needing a live backend to authenticate
  against.
- **`workflows/`** - full multi-step journeys against a live backend:
  - `full-lifecycle.spec.ts` - the Phase 4 brief's core acceptance scenario (CVE →
    Experiment Studio → Approve → Run → Verdict → Evidence), run as a single ADMIN
    account (ADMIN is an intentional override of self-approval blocking).
  - `phase6-acceptance.spec.ts` - the V2 Phase 6 final-release acceptance suite, eight
    scenarios (A-H) covering what Phase 6 added on top of that core journey: auth/session
    lifecycle, RBAC enforcement (UI *and* a direct API call), self-approval blocking
    across two real accounts, the audit trail, AI advisory-only assessments, revalidation,
    threat-intelligence sync, and post-auth graceful degradation.

  Needs the full stack running (`docker compose up` from the repo root) with at least one
  ingested, supported-domain CVE in the priority queue, and one bootstrap ADMIN account
  (`phase6-acceptance.spec.ts` creates every other account - RESEARCHER/REVIEWER/VIEWER -
  itself via the Users page, so nothing else needs pre-seeding). Only runs when
  `RUN_E2E_LIVE=1`:

  ```sh
  docker compose up -d
  .venv/Scripts/zeroshield create-admin --username e2e-admin --password "<a strong password>"
  RUN_E2E_LIVE=1 E2E_ADMIN_USERNAME=e2e-admin E2E_ADMIN_PASSWORD="<same password>" npm run test:e2e
  ```

  These specs were written but **not executed** against a live stack in the session that
  wrote them - no Docker daemon was available in that environment (the smoke/ tier *was*
  run and passes). Run the workflows/ tier once against a live stack before trusting it as
  a passing regression suite; selectors may need small adjustments once seeded data is in
  place.
