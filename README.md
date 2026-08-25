# ZeroShield

A sandbox-based validation platform for zero-click vulnerability mitigations. ZeroShield takes a documented VPN or Telecom zero-click CVE failure pattern, runs the **same synthetic test set** through a **baseline** (vulnerable-shaped) processing strategy and a **mitigation** (hardened) processing strategy, and produces a factual, hash-verified evidence bundle comparing the two. It never targets real systems and never uses live exploit payloads — every dataset is synthetic and generated deterministically.

On top of that core validation engine sits a full platform: automated CVE intelligence ingestion, an experiment-authoring studio with an approval workflow, a sandboxed executor, a deterministic verdict engine, an optional advisory-only AI research assistant, authentication/RBAC, an audit trail, and operational monitoring.

Detailed internal reference material (architecture deep-dive, requirements traceability, deployment runbooks, security audit notes) is kept in a local `docs/` folder that isn't published in this repository — everything needed to run and understand the system is in this README.

## Contents

- [Getting started](#getting-started)
- [Running it](#running-it) — Docker / native / CLI / tests
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)

## Getting started

**Requirements:** Python 3.12+, Node.js 20+ (for the web app), and Docker Desktop (recommended — runs everything for you, including the message broker and object storage).

The fastest way to get a working instance:

```powershell
git clone <this-repo>
cd ZeroShield
docker compose up --build
```

This starts every service — the web app, API, worker, PostgreSQL, RabbitMQ, MinIO, and monitoring. First build takes a few minutes; later starts are fast.

There is no seeded account, so bootstrap the first administrator:

```powershell
docker compose exec api zeroshield create-admin --username <you> --password "<12+ characters>"
```

Then open **http://localhost:3001** and sign in. Everything else (creating researcher/reviewer accounts, ingesting CVEs, building experiments) happens from the web UI from there.

## Running it

### Option A — Docker Compose (everything, recommended)

```powershell
docker compose up --build
```

| Service | URL | Notes |
|---|---|---|
| Web app (primary UI) | http://localhost:3001 | Mission Control, Threat Intel, Experiment Studio, Approvals, Runs, Evidence |
| API / Swagger | http://localhost:8000/docs | Interactive REST API explorer |
| Dashboard (legacy) | http://localhost:8502 | Read-only Streamlit view, no login |
| Grafana | http://localhost:3000 | login `zeroshield` / `zeroshield123` |
| Prometheus | http://localhost:9090 | |
| RabbitMQ management | http://localhost:15673 | login `guest` / `guest` |
| MinIO console | http://localhost:9003 | login `zeroshield` / `zeroshield123` |

Anything ZeroShield generates (evidence, exports, job records) lands in `results/`, `overleaf_exports/`, and `jobs/` on your machine — Docker bind-mounts these, nothing stays trapped in a container. Stop everything with `docker compose down`.

A single CLI command can also be run against the built image without starting the rest of the stack:

```powershell
docker run --rm zeroshield:latest zeroshield --help
```

### Option B — running natively

Install the backend into a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Add extras as needed for the interface(s) you're running — see [Configuration](#configuration).

**Web app** (needs the API running separately, see below):

```powershell
cd apps/web
npm install
npm run dev
```

Open http://localhost:3000 (targets `http://localhost:8000` by default; override with `API_BASE_URL`).

**API + async runs** — the API only *queues* a run; a separate worker process executes it, so both a broker and a worker need to be running:

```powershell
docker compose up -d rabbitmq postgres      # broker + auth/run-history database
.\.venv\Scripts\python.exe -m pip install -e ".[api,queue,db,auth,dev]"
$env:DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\zeroshield.exe create-admin --username alice --password "a strong password, 12+ chars"

# in a second terminal — the worker
.\.venv\Scripts\python.exe -m zeroshield.worker

# in a third terminal — the API
.\.venv\Scripts\python.exe -m uvicorn zeroshield.api.app:app --reload
```

Swagger is then at http://localhost:8000/docs — every route except `/health`, `/metrics`, and `/auth/login` requires signing in first (`POST /auth/login` in Swagger; the session cookie is reused automatically for the rest of the page).

**Dashboard** (legacy, read-only, no login):

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dashboard,dev]"
.\.venv\Scripts\python.exe -m streamlit run src/zeroshield/dashboard/app.py
```

Opens at http://localhost:8501. Lets you pick a bundled experiment, inspect its safety-check status, run it, and browse results/evidence — it can't submit anything the web app's approval workflow doesn't already govern.

### The command line

```powershell
zeroshield validate-experiment experiments\ZC-VPN-EXP-001.json --context local_unit_test
zeroshield run experiments\ZC-VPN-EXP-001.json --context local_unit_test
zeroshield compare results\ZC-VPN-EXP-001
zeroshield verify-evidence results\ZC-VPN-EXP-001\RUN-1234567890
zeroshield create-admin --username alice --password "..."
```

- `validate-experiment` — schema + dataset + safety-policy check, without executing anything.
- `run` — executes baseline and mitigation, writes evidence to `results/`. Refuses to run if the safety policy denies it.
- `compare` — prints an already-generated `comparison.json`; never re-runs anything.
- `verify-evidence` — checks a run's artefacts against its manifest's integrity hash.
- `create-admin` — bootstraps the first login (requires `DATABASE_URL`).

Both bundled experiments (`ZC-VPN-EXP-001`, `ZC-TELECOM-EXP-001`) ship as `draft`, so `--context local_unit_test` is what lets you exercise them locally; the strict `experiment_run` context correctly refuses anything unapproved.

### Tests

```powershell
.\.venv\Scripts\python.exe -m pytest        # backend: unit + integration, no external services required
cd apps/web && npm test                     # frontend unit/component tests
cd apps/web && npm run test:e2e             # Playwright, smoke tier — no backend needed
```

A handful of integration tests opt into real infrastructure (a live RabbitMQ broker, a live Postgres database, a full live-stack Playwright run) and self-skip unless you explicitly set their `ZEROSHIELD_E2E_*` environment variable — see the test files under `tests/integration/` and `apps/web/e2e/`.

## Configuration

Nothing below is required for local development without Docker — the CLI, dashboard, and the synchronous parts of the API/tests all work with zero environment variables set.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | *(unset)* | PostgreSQL connection string — required for auth, threat-intel, and the run-lifecycle history. Without it, those routes are unavailable/no-op; core validation still runs. |
| `RABBITMQ_URL` | `amqp://guest:guest@localhost:5672/` | Broker connection used by both the API and the worker. |
| `ZEROSHIELD_EVIDENCE_BACKEND` | `local` | `local` (files under `results/`) or `minio` (S3-compatible object storage). |
| `MINIO_ENDPOINT` / `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | `localhost:9000` / `zeroshield` / `zeroshield123` | Only read when the MinIO backend is selected. |
| `AI_PROVIDER` / `ANTHROPIC_API_KEY` / `AI_MODEL` | *(unset → disabled)* | Enables the optional AI Research Analyst. Every route works with it unset, just answering "unavailable". |
| `NVD_API_KEY` / `GITHUB_TOKEN` | *(unset)* | Optional, raise rate limits on the CVE intelligence connectors. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(unset → no exporter)* | Distributed tracing collector endpoint. |

Install extras from `pyproject.toml` as needed, e.g. `pip install -e ".[api,queue,db,auth,dev]"`. Available extras: `dashboard`, `api`, `queue`, `storage`, `db`, `intelligence`, `excel`, `ai`, `auth`, `observability`, `dev`.

Copy `.env.example` to `.env` to override default local credentials (Postgres/MinIO/Grafana passwords) — every default works with no `.env` file at all.

## How it works

### The core idea

Every "experiment" is a JSON document (`ExperimentDefinition`) describing a domain (VPN or Telecom), a synthetic dataset, and two processing strategies: a **baseline** that reproduces the vulnerable behaviour and a **mitigation** that reproduces the hardened fix. Running an experiment feeds the identical dataset through both strategies, records what each one did case by case, computes metrics (block rate, false-positive/negative rate, latency), and writes a hash-verified evidence bundle — never opinion, always a factual comparison.

### Layered architecture

```mermaid
flowchart TB
    L1["Threat intelligence<br/>NVD / CISA KEV / EPSS / GitHub Advisories → prioritised CVEs"]
    L2["Experiment definition<br/>domain packs, templates, synthetic dataset generators"]
    L3["Governance<br/>draft → review → approval, before anything can run"]
    L4["Execution<br/>sandboxed baseline + mitigation strategies"]
    L5["Evidence & metrics<br/>hash-verified manifests, comparison reports"]
    L6["Continuous assurance<br/>control effectiveness, regression detection, revalidation"]

    L1 --> L2 --> L3 --> L4 --> L5 --> L6
```

### Request flow

Every interface (CLI, dashboard, API, worker) is a thin wrapper over the same core — none of them re-implement validation, safety checks, or metrics:

```mermaid
flowchart LR
    CLI["CLI"] --> SVC
    DASH["Dashboard"] --> SVC
    API["API"] --> SVC
    WORKER["Worker"] --> SVC
    SVC["services.experiment_service"] --> ORCH["orchestration"]
    ORCH --> RUNNER["ExperimentRunner"]
    RUNNER --> POLICY["SafetyPolicy<br/>(evaluated before anything runs)"]
    RUNNER --> STRAT["baseline / mitigation strategies"]
    ORCH --> REPO["EvidenceRepository<br/>(local files or MinIO)"]
```

A synchronous CLI run does all of this in one process. Through the API, `POST /experiments/{id}/runs` only queues a `RunJobMessage` on RabbitMQ and returns immediately — a separate worker process consumes it, runs the same engine, and updates job status (`queued → running → completed/denied/failed`), polled via `GET /jobs/{job_id}`.

### What each layer actually is

| Layer | Responsibility | Key modules |
|---|---|---|
| Threat intelligence | Ingests and deduplicates CVEs from NVD/CISA KEV/EPSS/GitHub Advisories, scores a deterministic priority, classifies VPN/Telecom relevance | `zeroshield.intelligence` |
| Domain packs & templates | Declare which strategies, datasets, and metrics are valid for a domain; versioned, never overwritten | `zeroshield.domain_packs`, `zeroshield.templates` |
| Dataset generators | Produce deterministic, SHA-256-hashed synthetic test sets from a seed + config — no real exploit content | `zeroshield.generators` |
| Experiment Studio | Builds an `ExperimentVersion` from a domain pack + template + dataset, and drives it through `DRAFT → READY_FOR_REVIEW → UNDER_REVIEW → APPROVED/REJECTED → RETIRED` | `zeroshield.studio` |
| Safety policy | Evaluates a fixed set of rules (no real-system targeting, synthetic-only data, no weaponised payloads, must be approved before a real run) before every execution, no exceptions | `zeroshield.policies` |
| Sandbox | Wraps every strategy call with a strategy allow-list, a timeout, a network-access guard, and a memory cap | `zeroshield.sandbox` |
| Execution | Runs baseline and mitigation strategies against the dataset and records per-case outcomes | `zeroshield.runners`, `zeroshield.strategies`, `zeroshield.worker` |
| Evidence & metrics | Hash-verified run manifests, before/after comparison reports | `zeroshield.repositories`, `zeroshield.metrics` |
| Verdict | Deterministic, threshold-based EFFECTIVE / PARTIALLY_EFFECTIVE / INEFFECTIVE / REGRESSION outcome over a comparison report | `zeroshield.verdict` |
| Continuous assurance | Binds runs to a Control/ControlVersion, aggregates effectiveness, detects regressions, and queues revalidation on new triggers (KEV/EPSS changes, advisory updates, staleness) | `zeroshield.assurance` |
| AI research assistant (optional) | Advisory-only: failure-pattern classification, mitigation-gap analysis, CVE similarity narration, template/draft suggestions. Every output is persisted unreviewed and can never approve, execute, or alter anything itself | `zeroshield.ai` |
| Auth & governance | Session-based login, four roles (viewer/researcher/reviewer/admin) enforced server-side on every route, self-approval blocking, an append-only audit trail | `zeroshield.auth`, `zeroshield.audit` |
| Observability | Prometheus metrics, structured JSON logs, OpenTelemetry tracing across the API → queue → worker hop | `zeroshield.observability` |

### Interfaces

- **`apps/web/`** — the primary Next.js/React/TypeScript UI. Talks to the FastAPI backend exclusively, never to Postgres/MinIO/RabbitMQ/Python directly (see `apps/web/src/lib/api/client.ts`, its one point of contact with the backend).
- **`src/zeroshield/api/`** — the FastAPI REST backend every other interface (including the web app) depends on.
- **`src/zeroshield/dashboard/`** — the legacy Streamlit dashboard, read-only, kept for quick local browsing.
- **`src/zeroshield/cli/`** — the `zeroshield` console script for scripted/local single-run use.
- **`src/zeroshield/worker/`** — consumes queued jobs (experiment runs, intelligence syncs) from RabbitMQ and executes them.

### Data flow on disk

| Path | Contents |
|---|---|
| `experiments/` | `ExperimentDefinition` JSON files, auto-discovered by every interface |
| `test_data/` | Synthetic `TestSet` JSON files referenced by experiments |
| `results/` | Generated evidence: `<experiment_id>/<run_id>/manifest.json` + artefacts, `<experiment_id>/comparison.json` |
| `jobs/` | Async job status records, the API/worker's polling side-channel |
| `overleaf_exports/` | Generated write-up export files |

### Safety and security, in short

- **Safety policy is code, not convention.** `SafetyPolicy` runs before every execution and refuses anything targeting a real system, carrying non-synthetic data, using weaponised payloads, or lacking approval outside a local test context — enforced identically regardless of which interface triggered the run.
- **Evidence is immutable.** A run's manifest, once written, can never be silently overwritten.
- **Authentication & RBAC.** Argon2id-hashed passwords, opaque server-side sessions, account lockout, and four roles with no implicit hierarchy — every route names its exact allowed roles explicitly and enforces it server-side, never trusting the UI to hide a button.
- **Self-approval is blocked.** Whoever created an experiment version cannot also approve it (an administrator override is explicit and logged).
- **Everything security-relevant is audited.** An append-only audit trail records every session, approval, run, and configuration change with an actor, a target, and a timestamp.

### Tech stack

Python 3.12 (FastAPI, Pydantic, SQLAlchemy/Alembic, Streamlit) · Next.js/React/TypeScript/Tailwind · PostgreSQL · RabbitMQ · MinIO (S3-compatible) · Prometheus/Grafana · Docker Compose.

## Repository layout

```
apps/web/            Next.js frontend
src/zeroshield/       Python backend (API, CLI, worker, dashboard, domain logic)
alembic/              Database migrations
experiments/          Bundled ExperimentDefinition JSON files
test_data/            Synthetic datasets referenced by experiments
tests/                Backend test suite (unit, integration, security)
docker-compose.yml    Full local stack definition
Dockerfile            Backend image
```
