# E2E tests

Two tiers, gated in `playwright.config.ts`:

- **`smoke/`** - navigation, empty/error states, 404s, accessibility basics. Needs no
  backend and runs on every `npm run test:e2e`. This is what actually ran and passed in
  the session that wrote this app.
- **`workflows/`** - the full CVE → Experiment Studio → Approve → Run → Verdict →
  Evidence journey from the Phase 4 brief. Needs the full stack running
  (`docker compose up` from the repo root) with at least one ingested, supported-domain
  CVE in the priority queue. Only runs when `RUN_E2E_LIVE=1`:

  ```sh
  docker compose up -d
  RUN_E2E_LIVE=1 npm run test:e2e
  ```

  These specs were written but **not executed** in the session that added Phase 4 - no
  Docker daemon was available in that environment. Run them once against a live stack
  before trusting them as a passing regression suite; selectors may need small
  adjustments once seeded data is in place.
