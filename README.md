# ZeroShield

A Sandbox-Based Validation Framework for Zero-Click Vulnerability Mitigations — a defensive R&D prototype that converts selected VPN and Telecommunications zero-click CVE research into safe, reproducible, synthetic mitigation-validation experiments.

Status: **Milestones 1–30 complete** — the core validation engine (experiment models, safety policy, VPN/Telecom baseline and mitigation strategies, metrics, evidence generation, Overleaf export), a first-release command-line interface, a Streamlit demonstration dashboard, a FastAPI REST interface, a Docker image/Compose setup, asynchronous experiment execution via RabbitMQ and a worker process, an optional S3-compatible (MinIO) evidence storage backend alongside the default local one, Prometheus/Grafana operational monitoring, end-to-end tests exercising the CLI, dashboard, and API/worker through their real interface boundaries, a dedicated security/failure-path test suite (path traversal, evidence immutability, malformed-queue-message robustness, dataset secret scanning, a static dangerous-primitive tripwire, and a dependency vulnerability scan), a documentation reference set (`docs/`), architecture documentation with diagrams, a guided demonstration workflow, and a final requirement-by-requirement traceability and SRS compliance review. This completes the SRS's optional-infrastructure list (Docker, RabbitMQ, MinIO, Prometheus, Grafana). Milestone 24 was folded into Milestone 30 (evidence repository/retention policy, resolved as D-05 — see [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md)). The compliance review found the engineering baseline essentially complete, with the remaining open items (two experiments still `draft`/unapproved, several §17 open decisions) being supervisor decisions this solo placement execution has no live reviewer to close — documented explicitly rather than glossed over.

Authoritative requirements source: `ZC_Mitigation_Validation_Framework_SRS.docx` (draft, pending supervisor approval).

**V2 status:** ZeroShield is evolving into "ZeroShield — Continuous Mitigation Assurance Platform" per `ZeroShield Improvement Plan.docx`'s six-phase roadmap, preserving and extending the V1 core above rather than replacing it.

- **Phase 1 (Platform Foundation) is complete**: PostgreSQL + Alembic migrations for a rich, auditable run-lifecycle event trail (`zeroshield.repositories.PostgresRunRepository`, additive to the existing file-based job status), and MinIO as the default evidence backend for the containerised (Docker Compose) deployment. Both are optional infrastructure — every existing CLI/dashboard/bare-Python/test workflow above is unchanged and requires neither. See [`docs/ARCHITECTURE.md` §6a](docs/ARCHITECTURE.md#6a-v2-platform-foundation-postgresql-run-lifecycle-system-of-record).
- **Phase 2 (Threat Intelligence & Prioritisation) is complete**: automated NVD/CISA KEV/EPSS/GitHub Advisory ingestion, deduplication, field-level history, and a deterministic, explainable ZeroShield Validation Priority identifying VPN/Telecom `ValidationCandidate`s — replacing the manual CVE-to-Excel-to-experiment workflow (the workbook remains importable, never auto-executes anything). No AI. New endpoints: `GET /vulnerabilities`, `GET /priority-queue`, `GET /sources`/`/integrations`, `POST /intelligence/sync`. Requires `DATABASE_URL` (PostgreSQL is the system of record here, not optional). See [`docs/ARCHITECTURE.md` §6b](docs/ARCHITECTURE.md#6b-v2-phase-2-threat-intelligence--prioritisation) and [`docs/HANDOVER.md`](docs/HANDOVER.md#threat-intelligence--prioritisation-v2-phase-2).
- **Phase 3 (Advanced Validation Platform) is complete**: a Domain Pack framework (VPN/Telecom, migrating the existing strategies unchanged), versioned Validation Templates, deterministic synthetic dataset generators, an Experiment Studio backend that replaces hand-authoring experiment JSON, an explicit DRAFT→READY_FOR_REVIEW→UNDER_REVIEW→APPROVED/REJECTED→RETIRED approval workflow (never bypassing `SafetyPolicy`), a strengthened local `SandboxExecutor` (allow-list, timeout, network guard, resource limits — not Kubernetes), and a deterministic, threshold-based verdict engine. New endpoints: `GET /domain-packs`, `POST /experiment-versions`, the approval-transition routes, `POST /experiment-versions/{id}/runs`, `GET /experiments/{id}/verdict`. No AI. See [`docs/ARCHITECTURE.md` §6c](docs/ARCHITECTURE.md#6c-v2-phase-3-advanced-validation-platform) and [`docs/HANDOVER.md`](docs/HANDOVER.md#advanced-validation-platform-v2-phase-3).
- **Phase 4 (Professional Web Application) is complete**: a Next.js/React/TypeScript app (`apps/web/`) is now the primary ZeroShield interface, consuming FastAPI exclusively (never Postgres/MinIO/RabbitMQ/Python directly). Mission Control dashboard, Threat Intelligence (searchable vulnerabilities, priority queue), a multi-step Experiment Studio wizard (CVE → domain pack → template → dataset config → metrics → narrative → draft/submit), Approvals, a live SSE-driven Runs view, per-experiment Results/Verdict, an Evidence Vault, and System/Integrations/Health views. The Streamlit dashboard (below) is kept as a legacy, read-only view — its run-execution path is disabled so it can't bypass the web app's approval-gated workflow. Runs alongside the rest of the stack via `docker compose up` (port 3001) or standalone (`cd apps/web && npm run dev`). See [`apps/web/README.md`](apps/web/README.md).

This README covers step-by-step walkthroughs for each interface. For a narrower, more formal reference, see `docs/`:

- [`docs/HANDOVER.md`](docs/HANDOVER.md) — what ZeroShield is, setup, execution, extension, and safety controls, in one place (the SRS's required "handover guide").
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the seven-layer logical architecture, design patterns, component/deployment views, and run-flow sequence diagrams, each grounded in and cross-referenced to the actual code.
- [`docs/DEMONSTRATION.md`](docs/DEMONSTRATION.md) — a ~10-minute guided walkthrough for demonstrating ZeroShield to a supervisor/reviewer, including a live reproducibility check.
- [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) — every `zeroshield` CLI command and argument.
- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — every environment variable and dependency extra.
- [`docs/TESTING.md`](docs/TESTING.md) — the test suite in detail, including the security suite and known gaps.
- [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) — the Milestone 30 requirement-by-requirement SRS compliance review and D-05 (evidence retention policy) resolution.

## Running the ZeroShield Web Application

The primary way to use ZeroShield (V2 Phase 4) - a full web app (`apps/web/`) covering
Mission Control, Threat Intelligence, Experiment Studio, Approvals, live runs,
verdicts/evidence, and system health, with no terminal, Swagger, or JSON editing
required day-to-day. The easiest way to run it is the same `docker compose up` command
in [Running ZeroShield with Docker](#running-zeroshield-with-docker) below - it starts
this app alongside everything else on <http://localhost:3001>. See
[`apps/web/README.md`](apps/web/README.md) for running it standalone (`npm run dev`)
against an already-running API.

## Running the ZeroShield Dashboard (legacy)

ZeroShield's original visual dashboard, kept read-only for browsing existing
experiments/results/evidence - use the web application above to submit a run. This
section assumes you have never used a terminal before.

### 1. Open a terminal in the project folder

- Open **PowerShell** (search for it in the Start menu).
- Move into the ZeroShield project folder by typing (adjust the path if your copy is somewhere else):

  ```powershell
  cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
  ```

### 2. One-time setup (only needed the first time, or after an update)

Install the project and the dashboard's dependencies into its virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dashboard,dev]"
```

You only need to do this again if you pull new code changes.

### 3. Launch the dashboard

From the project folder, run:

```powershell
.\.venv\Scripts\python.exe -m streamlit run src/zeroshield/dashboard/app.py
```

A browser tab should open automatically at `http://localhost:8501`. If it doesn't, open that address in your browser manually.

### 4. Using the dashboard

- The **sidebar** lets you pick which experiment to look at (e.g. `ZC-VPN-EXP-001` or `ZC-TELECOM-EXP-001`).
- The **Overview** tab explains what ZeroShield does.
- The **Experiment & Safety** tab shows the experiment's details and whether ZeroShield's safety check currently allows it to run. If it's denied, the reason is shown and the "Run Experiment" button is disabled — this cannot be bypassed from the dashboard.
- Click **Run Experiment** to execute it. This runs the same underlying engine used by the command line — nothing about the results is invented or adjusted for display.
- The **Results**, **Test Cases**, and **Evidence** tabs then show what happened, including a case-by-case before-vs-after comparison.
- The **Overleaf Export** tab produces a factual summary file for manual inclusion in the research write-up — it never edits the shared Overleaf document directly.

### 5. Closing the dashboard

Go back to the PowerShell window and press `Ctrl+C`.

## Running the ZeroShield API

ZeroShield also includes a REST API, so other programs (or you, using a browser-based test page) can list, validate, run, and inspect experiments over HTTP. This section assumes you have never used a terminal or an API before.

### 1. Open a terminal in the project folder

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
```

### 2. One-time setup (only needed the first time, or after an update)

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
```

### 3. Start RabbitMQ and the worker (required for runs to actually complete)

As of Milestone 21, submitting a run no longer executes it directly — the API queues it on RabbitMQ and a separate **worker** process picks it up. Without a running broker and worker, a submitted run will just sit as `queued` forever. The simplest way to get RabbitMQ running is via Docker, even if you're running the API itself natively:

```powershell
docker compose up -d rabbitmq
```

Then, in a second PowerShell window, start the worker:

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
.\.venv\Scripts\python.exe -m pip install -e ".[queue,dev]"
.\.venv\Scripts\python.exe -m zeroshield.worker
```

Leave this window open too — the worker keeps running and processing jobs as long as this command is running.

### 4. Start the API

In a third PowerShell window:

```powershell
.\.venv\Scripts\python.exe -m uvicorn zeroshield.api.app:app --reload
```

Leave this window open — the API keeps running as long as this command is running.

### 5. Open Swagger (the interactive API test page)

In your browser, go to:

```
http://localhost:8000/docs
```

This page lists every endpoint and lets you send real requests by clicking "Try it out" — you never need to write an HTTP request by hand.

### 6. List experiments

In Swagger, open **GET /experiments** → "Try it out" → "Execute". You'll see `ZC-VPN-EXP-001` and `ZC-TELECOM-EXP-001` (or any other experiment file dropped into the `experiments/` folder — nothing is hard-coded).

### 7. Validate an experiment

Open **POST /experiments/{experiment_id}/validate** → "Try it out" → set `experiment_id` to `ZC-VPN-EXP-001` → in the request body put:

```json
{"execution_context": "local_unit_test"}
```

→ "Execute". You'll see whether ZeroShield's safety policy currently allows it to run, and why if not.

### 8. Run a draft experiment using local_unit_test

Both bundled experiments are still in `draft` review status, so the strict `experiment_run` context will always correctly refuse them (this is the safety gate working as intended, not a bug). To actually execute one for a local demonstration, use **POST /experiments/{experiment_id}/runs** with:

```json
{"execution_context": "local_unit_test"}
```

→ "Execute". This queues the run and returns immediately with a `job_id` and `status: "queued"` — it does not run the experiment itself. The worker (started in step 3) picks the job up, runs it for real, and writes real evidence to `results/`.

Copy the `job_id`, then open **GET /jobs/{job_id}** → paste it in → "Execute". Keep re-running it (a few seconds apart) until `status` becomes `completed` (or `denied`/`failed`, with a reason) — that response also includes the key metrics and where the evidence was written.

### 9. Inspect results/evidence

Once a job has completed:

- **GET /experiments/{experiment_id}/results** — the baseline-vs-mitigation comparison from the most recent run.
- **GET /experiments/{experiment_id}/evidence** — factual evidence metadata (run IDs, dataset hash, integrity check) for the most recent run.

Both return `404` until an experiment has actually been run at least once.

### 10. Stop everything

Go back to each PowerShell window (uvicorn, the worker) and press `Ctrl+C`, then stop RabbitMQ:

```powershell
docker compose down
```

## Running ZeroShield with Docker

If you have Docker Desktop installed, you can run everything — API, dashboard, RabbitMQ, and the worker — without installing Python or any dependencies on your own machine at all. This is the easiest way to get asynchronous runs working, since it starts RabbitMQ and the worker for you automatically.

### 1. Install Docker Desktop

Download it from docker.com if you don't already have it, and make sure it's running (its whale icon appears in the system tray).

### 2. Build and start ZeroShield

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
docker compose up --build
```

The first build downloads and installs everything and can take a few minutes; later runs are much faster. This starts four containers: `rabbitmq`, `api`, `worker`, and `dashboard` — a run submitted through the API here is picked up and executed automatically, with no extra steps.

### 3. Open the tools

- API Swagger: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8502` (note: 8502, not Streamlit's usual 8501 — this avoids clashing with a locally-run, non-Docker dashboard on the same machine)
- RabbitMQ management UI (optional, for the curious): `http://localhost:15673` (login `guest`/`guest`)

They behave exactly like the non-Docker versions described above — same safety checks, same experiments, same real evidence generation.

### 4. Where results go

Anything ZeroShield generates while running in Docker (evidence, comparisons, Overleaf exports, job records) is written to the same `results/`, `overleaf_exports/`, and `jobs/` folders you'd see running it directly — Docker doesn't hide or lose this data, it's shared with your project folder automatically.

### 5. Stop everything

```powershell
docker compose down
```

### Using the command-line tool via Docker

One-off CLI commands can be run against the same image without starting the API/dashboard, for example:

```powershell
docker run --rm zeroshield:latest zeroshield --help
```

## Optional: MinIO evidence storage

By default, ZeroShield stores evidence (manifests, results, comparisons) as plain files under `results/`. As of Milestone 22, an S3-compatible alternative (`MinioEvidenceRepository`, in `zeroshield.repositories`) is also available, backed by [MinIO](https://min.io) — proving the evidence-storage design can be swapped without touching any research/orchestration code.

Running via Docker Compose (`docker compose up`) now uses MinIO as the default evidence backend for the `worker`/`dashboard` services (V2 Platform Foundation phase — set via `ZEROSHIELD_EVIDENCE_BACKEND=minio` in `docker-compose.yml`). Running natively without Docker (or under `pytest`), the default remains local file storage — nothing changes unless you set `ZEROSHIELD_EVIDENCE_BACKEND=minio` yourself. The CLI always uses local file storage regardless.

To select MinIO manually outside Docker:

```powershell
docker compose up -d minio
.\.venv\Scripts\python.exe -m pip install -e ".[storage,dev]"
$env:ZEROSHIELD_EVIDENCE_BACKEND = "minio"
```

Or construct one directly in Python: `zeroshield.repositories.minio_evidence_repository.default_minio_client()` (reads `MINIO_ENDPOINT`/`MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY`/`MINIO_SECURE`, defaulting to `localhost:9002` with the credentials set in `docker-compose.yml`) together with `MinioEvidenceRepository(client, bucket_name)` in place of `LocalEvidenceRepository`. The MinIO web console is at `http://localhost:9003` (login `zeroshield`/`zeroshield123`) if you want to browse stored evidence visually.

## Optional: PostgreSQL run-lifecycle history

As of the V2 Platform Foundation phase, ZeroShield can additionally record a rich, auditable run-lifecycle trail (`QUEUED → PREPARING → SAFETY_CHECK → RUNNING_BASELINE → RUNNING_MITIGATION → ANALYSING → GENERATING_EVIDENCE → COMPLETED`, or `DENIED`/`FAILED`) to PostgreSQL, alongside the existing file-based job status you already poll via `GET /jobs/{job_id}` (unchanged). This is **not** required to run ZeroShield: with no `DATABASE_URL` set, the API/worker use a no-op repository and behave exactly as before.

Running via Docker Compose starts a `postgres` service and wires `DATABASE_URL` for `api`/`worker` automatically. To try it outside Docker:

```powershell
docker compose up -d postgres
.\.venv\Scripts\python.exe -m pip install -e ".[db,dev]"
$env:DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m alembic upgrade head
```

## Optional: Prometheus & Grafana monitoring

As of Milestone 23, the API and worker expose **operational** metrics — request counts and latency, how many runs were submitted, how many jobs completed/were denied/failed, how long jobs took. These describe how the *system* is behaving, not what an experiment found: they are always separate from, and never a substitute for, the scientific evidence under `results/` or `GET /experiments/{id}/results`.

- The API serves its own metrics at `GET /metrics` (visible in Swagger).
- The worker serves its own metrics on a separate small HTTP server, since it isn't otherwise an HTTP service.

To visualise them, start the monitoring stack alongside the rest of ZeroShield:

```powershell
docker compose up -d
```

Then open:

- **Prometheus**: `http://localhost:9090` — try the query `zeroshield_worker_jobs_processed_total` after running an experiment.
- **Grafana**: `http://localhost:3000` (login `zeroshield`/`zeroshield123`) — the "ZeroShield Operational Metrics" dashboard is pre-loaded automatically (no manual setup), showing API request rate, worker job outcomes, average job duration, and submitted-run counts.

Submit a run via Swagger or the CLI, wait about 15–30 seconds for the next Prometheus scrape, then refresh the Grafana dashboard to see it reflected.

## Security testing

As of Milestone 26, `tests/security/` exercises the SRS's §10.3 threat model and §11.1 "Security" test level directly, alongside two fixes this milestone made to close real gaps against the SRS's own claims:

- **Evidence immutability** (`test_evidence_immutability.py`) — `LocalEvidenceRepository`/`MinioEvidenceRepository` now reject a second `save_run_evidence()` call for the same `experiment_id`/`run_id` (raising `EvidenceAlreadyExistsError`) instead of silently overwriting existing evidence. `comparison.json` is deliberately exempt — it is a "latest comparison" pointer, not per-run evidence.
- **Malformed queue message robustness** (`test_queue_message_robustness.py`) — the worker's `handle_message_body()` never raises, for a wide range of malformed/adversarial message bodies (empty, non-JSON, missing fields, invalid enum values, an embedded NUL byte, binary garbage, an oversized payload). Before this fix, a single malformed message would crash the consume loop and, since it was never acked, be redelivered and crash the worker again forever.
- **Comprehensive path-traversal sweep** (`test_path_traversal_comprehensive.py`) — every id-accepting API route (`/experiments/{id}`, `/experiments/{id}/results`, `/experiments/{id}/evidence`, `/experiments/{id}/validate`, `/experiments/{id}/runs`, `/jobs/{id}`) against a shared list of malicious ids, plus a canary-file check proving nothing outside the sanctioned `results_root`/`jobs_dir`/`experiments_dir` is ever read back into a response.
- **Dataset secret scanning** (`test_static_analysis_guards.py`, SAFE-006) — scans every real `experiments/*.json` and `test_data/**/*.json` file for secret-shaped strings (API keys, private key blocks, bearer tokens, generic credential assignments).
- **Static dangerous-primitive tripwire** (`test_static_analysis_guards.py`, AC-09) — greps `src/` for `eval`/`exec`/`os.system`/`subprocess(..., shell=True)`/`pickle`/`__import__`. None exist today; this fails the build the day one is added without a deliberate, reviewed allowlist entry.
- **Dependency vulnerability scan** (`test_dependency_vulnerabilities.py`) — runs the real `pip-audit` CLI against the installed environment. Requires outbound network access to the OSV/PyPI advisory database; skips (rather than fails) if that's unavailable, since no network is not evidence of no vulnerabilities.

**Deliberately out of scope for this milestone** (testing, not infrastructure/design work):

- **SAFE-005** (network egress denied by default for sandbox containers) — no sandbox container execution exists yet to test against.
- **Cryptographic queue-payload signing** — the SRS's §10.3 "signed/validated payloads" threat-model line is currently satisfied by schema validation only (`RunJobMessage.model_validate_json`, `extra="forbid"`); message-level signing is a design addition, not something an automated test can retrofit.

## Running the tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

This runs the full suite (unit + integration) with **no external services required** — the async/queue tests use a fake in-process publisher, exactly as the API does when tested. `tests/integration/` additionally contains real, cross-process end-to-end tests:

- `test_cli_full_workflow.py` / `test_dashboard_full_workflow.py` — run automatically, no setup needed (real subprocess/real Streamlit rendering, but no external services).
- `test_api_worker_real_broker.py` — publishes to and consumes from a **real** RabbitMQ broker instead of a fake, proving the actual message-queue mechanics work. This one is skipped by default and only runs if you explicitly opt in:

  ```powershell
  docker compose up -d rabbitmq
  $env:ZEROSHIELD_E2E_RABBITMQ_URL = "amqp://guest:guest@localhost:5673/"
  .\.venv\Scripts\python.exe -m pytest tests/integration/test_api_worker_real_broker.py
  ```

  It deliberately never falls back to a default host/port for this — an earlier version did, and on a machine with an unrelated RabbitMQ container already using the standard port, it silently connected to that instead of a ZeroShield broker.
