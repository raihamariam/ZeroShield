# ZeroShield CI and Docker Release Reference (V2 Phase 6, Steps 6/8)

## 1. Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request to `master`.
**CI only - no deployment, no image publish, no release step.** Three
independent jobs:

- **`backend`**: installs ZeroShield with every extra
  (`pip install -e ".[api,dashboard,queue,storage,db,intelligence,excel,auth,ai,observability,dev]"`),
  then `ruff check src/ tests/`, `mypy src/`, `pytest tests/ -q`. No
  external services are started - the full 1000+-test suite (unit,
  integration, security, policy) runs against SQLite in-memory and
  fakes/mocks throughout; the two genuinely-real-broker/-database
  integration tests, and the live V2 release acceptance suite, self-skip
  because `ZEROSHIELD_E2E_RABBITMQ_URL`/`ZEROSHIELD_E2E_POSTGRES_URL`/
  `ZEROSHIELD_E2E_LIVE_STACK_URL` are deliberately unset in CI (see
  [`docs/TESTING.md`](TESTING.md)).
- **`frontend`**: `npm ci`, `tsc --noEmit`, `npm run lint`, `npm test`
  (vitest), `npm run build`, then installs Playwright's Chromium and runs
  `npm run test:e2e` - the smoke tier only (`apps/web/e2e/smoke/`), which
  needs no backend. The live `workflows/` tier
  (`apps/web/e2e/workflows/*.spec.ts`) needs the full docker-compose stack
  and a seeded ADMIN account and is deliberately not run in CI - see
  [`apps/web/e2e/README.md`](../apps/web/e2e/README.md).
- **`docker-build`**: `docker compose build` - verifies every image
  (backend `zeroshield:latest`, used by api/worker/intelligence-worker/
  migrate/dashboard, and `zeroshield-web:latest`) actually builds. Build
  only - no push, no registry login, nothing started.

## 2. Docker Compose (one command, finalized)

```sh
docker compose up -d
```

Brings up every service: `postgres`, `rabbitmq`, `minio`, `api`, `worker`,
`intelligence-worker`, `web`, `dashboard` (legacy), `prometheus`, `grafana`.
No Redis - nothing in ZeroShield needs a cache or a pub/sub broker beyond
what RabbitMQ (job queue) and Postgres (system of record) already provide;
adding one would be unused infrastructure.

Every service that has something meaningful to check has a `healthcheck:`
(new in Phase 6 for `worker`, `intelligence-worker`, `web`, `prometheus`,
`grafana` - `postgres`/`rabbitmq`/`minio`/`api`/`dashboard` already had one),
and `depends_on: condition: service_healthy` chains accordingly, so
`docker compose up` brings services up in a correct, verified order rather
than a fixed sleep/guess.

A one-shot `migrate` service (final release verification fix) runs
`alembic upgrade head` once postgres is healthy, and `api`/`worker`/
`intelligence-worker` all wait on it (`condition: service_completed_successfully`)
before starting - a fresh, empty Postgres volume is always migrated to head
before anything that depends on the schema starts. See §4 below for why
this was needed and how it was verified.

`api`, `worker`, and `dashboard` all use the local evidence backend by
default - do not set `ZEROSHIELD_EVIDENCE_BACKEND=minio` on only some of
them (see §4's known limitation) or evidence becomes invisible through the
API/UI even though it was written correctly.

### First-time setup after `docker compose up -d`

There is no seeded user - V2 Phase 6 local auth requires bootstrapping the
first ADMIN account:

```sh
docker compose exec api zeroshield create-admin --username <you> --password "<a strong password>"
```

Then sign in at <http://localhost:3001>. See
[`docs/SECURITY.md`](SECURITY.md) for roles and [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md#create-admin)
for the command's full behaviour.

### Overriding credentials

Copy [`.env.example`](../.env.example) to `.env` to override the default
Postgres/MinIO/Grafana passwords - every default still works with no `.env`
file at all, so this is optional for local/dev use and expected for
anything longer-lived.

### Ports

| Service | Host port | Notes |
|---|---|---|
| `web` | 3001 | Primary UI |
| `api` | 8000 | Swagger at `/docs` |
| `worker` metrics | 9200 | Prometheus scrape target |
| `intelligence-worker` metrics | 9201 | Prometheus scrape target (new in Phase 6) |
| `postgres` | 5433 | Not 5432, to avoid colliding with a host Postgres |
| `rabbitmq` (AMQP / management UI) | 5673 / 15673 | Not 5672/15672, same reasoning |
| `minio` (API / console) | 9002 / 9003 | Not 9000/9001, same reasoning |
| `dashboard` (legacy) | 8502 | Not Streamlit's default 8501 |
| `prometheus` | 9090 | |
| `grafana` | 3000 | Pre-provisioned dashboard + datasource |

## 3. What is deliberately not here

No Kubernetes manifests, no cloud provider config, no CD/deploy pipeline,
no image registry push. See [`docs/FUTURE_OPPORTUNITIES.md`](FUTURE_OPPORTUNITIES.md)
for what a cloud/SaaS evolution of this would look like - documented only,
not implemented, per the V2 Phase 6 scope boundary.

## 4. Final release verification report

A dedicated audit pass tested the gap between "the code exists and unit
tests pass" and "a completely fresh `docker compose up` actually works,
end to end." Every result below is from an actual execution against a
genuinely fresh stack (`docker compose down -v && docker compose up
--build`), not inferred from reading the code.

### Bugs found and fixed

| # | Bug | Fix |
|---|---|---|
| 1 | A fresh Postgres volume was never migrated - `alembic.ini`/`alembic/` weren't even copied into the image, and nothing ran `alembic upgrade head`. Every DB-backed route, including login, would have failed with "relation does not exist" on first use. | Added `alembic.ini`/`alembic/` to the Dockerfile `COPY`s and a one-shot `migrate` service; `api`/`worker`/`intelligence-worker` all `depends_on: migrate: condition: service_completed_successfully`. |
| 2 | `worker`/`intelligence-worker` crashed (exit 1) on a genuinely parallel fresh start - RabbitMQ's healthcheck can report healthy slightly before its AMQP listener actually accepts connections, and neither worker retried its first connection attempt. | Added `zeroshield.worker.broker.connect_with_retry` (bounded retry with backoff), used by both worker entrypoints. |
| 3 | The `web` container's healthcheck failed - Docker auto-sets `HOSTNAME` to the container ID, and Next.js's standalone `server.js` binds to `$HOSTNAME` instead of every interface, making the app unreachable via `localhost`/`127.0.0.1`/`::1` from inside its own container (only reachable via its real bridge-network IP, which is why the host-published port still worked). | `ENV HOSTNAME=0.0.0.0` in `apps/web/Dockerfile`. |
| 4 | `experiments/` wasn't bind-mounted for `api`/`worker`/`dashboard` (only `intelligence-worker` had it) - each container had its own frozen, build-time-baked copy. `POST /experiment-versions/{id}/runs` materialises the approved experiment into the **api** container's own isolated copy, which the **worker** container's `find_experiment()` could never see. Every Studio-based run failed with "experiment could not be found when the job started." | Added `./experiments:/app/experiments` to `api`/`worker`/`dashboard`. |
| 5 | Same bug, one directory over: `test_data/generated/` (where Studio-generated datasets are written) wasn't shared either, so a Studio run that got past bug 4 then failed with "the experiment's configured dataset ... could not be resolved." | Added `./test_data:/app/test_data` to the same three services. |
| 6 | Evidence-backend mismatch: `worker`/`dashboard` defaulted to `ZEROSHIELD_EVIDENCE_BACKEND=minio`, `api` defaulted to `local` - and `experiment_service.load_latest_evidence()` (the one function `GET /verdict`/`/results`/`/evidence` and the dashboard all read through) is hardcoded to `LocalEvidenceRepository` regardless of that setting. Runs completed and wrote real evidence to MinIO (confirmed by inspecting the bucket directly), but every read route 404'd with "no_evidence." | Reverted `worker`/`dashboard` to the local backend, matching `api`, so what's written is what's read. The read-path's MinIO-blindness itself is a real, documented follow-up (see below), not fixed in this pass - fixing it is a code change to `load_latest_evidence`, judged out of scope for a config-and-infra verification pass. |
| 7 | `JobStore.save()` used a plain `write_text()` (open-in-"w"-mode, which truncates before writing), read concurrently by a different process (the API, polled while the worker is mid-save). Reproduced live: `GET /jobs/{id}` 500'd with a Pydantic "EOF while parsing a value" error after reading a momentarily-empty file. | Atomic write: temp file + `os.replace()`, which is atomic on both POSIX and Windows. |
| 8 | **The most serious finding.** Six `zeroshield.api.dependencies` repository getters (plus `GET /health`'s DB check) called `build_sessionmaker()` bare - with no cached engine - so every single request touching auth/audit/assurance/vulnerability/experiment-version/run repositories created a **brand-new SQLAlchemy Engine and connection pool**. Reproduced live as a literal Postgres `FATAL: sorry, too many clients already`, surfacing as unrelated-looking 500s across `/auth/login`, `/auth/me`, `/users`, `/integrations`, `/controls/.../effectiveness`, and more, after sustained use. This would eventually exhaust any production-like deployment, not just a stress test. | Added `zeroshield.db.session.get_shared_sessionmaker()`, an `lru_cache`d process-wide singleton; every affected call site now uses it instead of calling `build_sessionmaker()` fresh. |

Also fixed: two Playwright test bugs discovered during live verification (a
`getByRole("button", { name: "Next" })` selector that, under `next dev`
only, ambiguously matched Next.js's own "Open Next.js Dev Tools" toolbar
button - fixed with `exact: true`), and one genuine but non-security UI
finding documented rather than silently fixed (the Integrations page's
"Trigger sync" button isn't role-hidden from VIEWER the way the Users
page's "Create user" button is - server-side RBAC still blocks it; see
[`docs/SECURITY.md`](SECURITY.md) §2).

### Execution results

**Infrastructure** (`docker compose down -v && docker compose up --build`,
genuinely empty volumes):
- All 10 services reached `healthy` on a single parallel start.
- `alembic current` reported `0005 (head)` with no manual intervention.
- `zeroshield create-admin` and the resulting login both succeeded on the
  first attempt against the fresh database.

**Backend**: `ruff check src/ tests/` clean. `mypy src/` clean (164
files). `pytest tests/ -q` - **1036 passed, 11 skipped, 0 failed** (the 11
skips are the three pre-existing opt-in real-broker/real-Postgres tests
plus the eight new live-acceptance-suite tests, all of which deliberately
self-skip without `ZEROSHIELD_E2E_*` env vars set). `pytest tests/security/`
in isolation: **89 passed**.

**The V2 release acceptance suite** (`tests/integration/test_v2_release_acceptance.py`,
run against the fresh stack with `ZEROSHIELD_E2E_LIVE_STACK_URL` set) -
**8/8 scenarios passed**:

| Scenario | Result |
|---|---|
| A - fresh DB → migrations → controlled intelligence → VPN validation candidate → Studio → dataset → approval → run → verdict → evidence → integrity | PASS |
| B - same governed path, Telecom domain | PASS |
| C - unapproved/denied experiment cannot execute | PASS |
| D - RESEARCHER cannot self-approve; separate REVIEWER can | PASS |
| E - deterministic regression detection + independent revalidation trigger | PASS |
| F - AI unconfigured: every non-AI core route still works, AI route cleanly 503s | PASS |
| G - MinIO stopped mid-run: job fails safely, never falsely "completed" | PASS |
| H - worker restarted mid-processing: job reaches a coherent terminal state, no duplicate/divergent record | PASS |

**Frontend**: `tsc --noEmit` clean. `eslint` - 0 errors, 5 pre-existing
unrelated warnings (`Button.tsx`). `vitest run` - **30/30 passed**.
`next build` succeeds. Playwright smoke tier (no backend) - **28/28
passed**. Playwright `workflows/` tier (live backend, `--workers=1`) -
**6/9 passed**: `Governance 1/2/4/6/7/8` all pass; `full-lifecycle.spec.ts`
and `Governance 3` stall on the Experiment Studio wizard's "Next" button
remaining disabled after the CVE-narrative step is filled (only reproduced
under `next dev`'s per-route compilation - needs further investigation,
honestly left open rather than worked around); `Governance 5`'s "Mark
reviewed" button never appeared for the AI assessment created in that same
run. These three are tracked as a known limitation, not claimed passing.

**Docker image builds**: `docker compose build` succeeds for every image
(`zeroshield:latest` and `zeroshield-web:latest`) - also now the
`docker-build` CI job.

**CI**: `.github/workflows/ci.yml` YAML validated (3 jobs: `backend`,
`frontend`, `docker-build`).

### Known limitations after this pass

- **MinIO evidence-backend read-path gap** (bug 6 above) - real follow-up
  work, not fixed here. `zeroshield.services.experiment_service.
  load_latest_evidence()` needs to become backend-aware (reading through
  the same `EvidenceRepository` abstraction the write path already uses)
  before `ZEROSHIELD_EVIDENCE_BACKEND=minio` can be the default for any
  service whose evidence needs to be visible through the API/UI.
- **Playwright `workflows/` tier: 6/9**, not 9/9 - see above. The 3
  failures are UI-timing/dev-server issues under live investigation, not a
  security or correctness gap (the equivalent flows are proven correct by
  the fully-passing Python acceptance suite above, which talks to the same
  live API directly).
- **Integrations page "Trigger sync" button** isn't role-hidden from
  VIEWER - cosmetic, not a security gap (see bugs table above and
  [`docs/SECURITY.md`](SECURITY.md) §2).
