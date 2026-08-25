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
  - `governance-acceptance.spec.ts` (formerly `phase6-acceptance.spec.ts`, renamed in the
    final release verification pass to stop implying these eight scenarios were the
    literal "Phase 6 acceptance gate A-H") - eight browser-driven checks, labelled
    "Governance 1-8", covering the UI-facing features Phase 6 added on top of that core
    journey: auth/session lifecycle, RBAC enforcement (UI *and* a direct API call),
    self-approval blocking across two real accounts, the audit trail, AI advisory-only
    assessments, revalidation, threat-intelligence sync, and post-auth graceful
    degradation. The actual, authoritative eight-scenario V2 release acceptance suite
    (fresh-DB VPN flow, Telecom flow, denied-run, self-approval, regression/revalidation,
    AI-disabled, MinIO-failure, worker-restart) lives outside Playwright, in
    `tests/integration/test_v2_release_acceptance.py` - several of those scenarios need
    infrastructure manipulation (stopping MinIO, restarting the worker container) that a
    browser test isn't a natural fit for.

  Needs the full stack running (`docker compose up` from the repo root) with at least one
  ingested, supported-domain CVE in the priority queue, and one bootstrap ADMIN account
  (`governance-acceptance.spec.ts` creates every other account - RESEARCHER/REVIEWER/VIEWER -
  itself via the Users page, so nothing else needs pre-seeding). Only runs when
  `RUN_E2E_LIVE=1`:

  ```sh
  docker compose up -d
  docker compose exec api zeroshield create-admin --username e2e-admin --password "<a strong password>"
  RUN_E2E_LIVE=1 E2E_ADMIN_USERNAME=e2e-admin E2E_ADMIN_PASSWORD="<same password>" \
    npx playwright test workflows/ --workers=1
  ```

  `--workers=1` is a real, observed recommendation, not stylistic: `next dev`
  compiles each route on first request, and Playwright's default
  `fullyParallel: true` hitting many distinct routes at once across several
  workers reliably starved the dev server under real testing, producing
  unrelated-looking navigation timeouts with no code defect behind them.
  This tier runs against `next dev`, not a production build, by design (it
  needs live hot-reload-free but still dev-configured behaviour matching
  local development) - see `docs/DEPLOYMENT.md`'s final release
  verification report for the actual, real execution results of this tier
  against a fresh stack, and its known limitations.
