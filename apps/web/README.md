# ZeroShield Web Application

The primary ZeroShield UI (V2 Phase 4) - Next.js (App Router) + React + TypeScript +
Tailwind CSS. It consumes the FastAPI backend exclusively: never PostgreSQL, MinIO,
RabbitMQ, or Python directly. See `src/lib/api/client.ts` for the one place that knows
how to reach the backend, and `src/lib/api/types.ts`, which mirrors
`src/zeroshield/api/schemas.py` field-for-field.

Replaces the Streamlit dashboard (`src/zeroshield/dashboard/app.py`) as the primary
interface - that dashboard is kept as a legacy, read-only view (its run-execution path
is disabled so it can't bypass this app's approval-gated workflow).

## Running locally (without Docker)

Requires the ZeroShield API running separately (`uvicorn zeroshield.api.app:app` from
the repo root - see the root `README.md`).

```bash
cd apps/web
npm install
npm run dev
```

Open <http://localhost:3000>. By default it targets `http://localhost:8000` for the
API; override with `API_BASE_URL` if the API is elsewhere.

## Running with Docker Compose

From the repo root:

```bash
docker compose up
```

This starts the full stack (Postgres, RabbitMQ, MinIO, the API, workers, the legacy
Streamlit dashboard, and this app) together. The web app is published on
**<http://localhost:3001>** (not 3000 - Grafana already uses that port in the same
compose file) and talks to the `api` service over the compose network.

## Project layout

- `src/app/` - routes (App Router). Each top-level nav item (Mission Control, Threat
  Intelligence, Validation, Assurance, Governance, System) has one or more pages here;
  `src/components/layout/nav-config.ts` is the single source of truth for the sidebar.
- `src/components/ui/` - the design system (Button, Card, Badge/StatusPill, Table,
  Field, Pagination, Skeleton, EmptyState, ErrorState, StatTile, ...).
- `src/components/features/` - page-specific interactive pieces (the Experiment Studio
  wizard, the live SSE run view, approval actions, run submission).
- `src/lib/api/` - the typed API client layer (one module per backend route group).
- `src/lib/` - small framework-free helpers (`experimentStudio.ts` validation,
  `generatorConfigs.ts` dataset-config field specs, `priority.ts` CVE→priority lookup).

## Testing

```bash
npm run test        # Vitest unit/component tests
npm run test:e2e     # Playwright - smoke tier by default (no backend needed)
RUN_E2E_LIVE=1 npm run test:e2e   # + full-lifecycle workflow spec, needs a live stack
```

See `e2e/README.md` for what each Playwright tier covers.

## Known API gaps

A few UI requirements exceed what the current FastAPI schemas return (draft
experiment-version content pre-approval, per-CVE affected products, result
case-category breakdowns, a generator config schema endpoint). Each affected page says
so explicitly rather than fabricating the missing data - see the "Phase 4 API gaps"
note left in this session's memory, or grep the codebase for "not exposed" /
"not yet available".
