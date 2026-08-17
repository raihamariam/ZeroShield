# ZeroShield Configuration Reference

Every environment variable and dependency extra ZeroShield's own code reads or requires, in one place. Docker Compose service credentials (e.g. Grafana's admin login) are documented separately at the end, since those configure the third-party images themselves, not ZeroShield code.

## Environment variables

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `RABBITMQ_URL` | API (`zeroshield.api.dependencies.get_rabbitmq_url`), worker (`zeroshield.worker.main.get_rabbitmq_url`) | `amqp://guest:guest@localhost:5672/` | Broker connection string both the job-submitting API and the consuming worker use. Must point at the **same** broker for jobs to actually be picked up. |
| `WORKER_METRICS_PORT` | worker (`zeroshield.worker.main.get_metrics_port`) | `9200` | Port the worker's own Prometheus metrics HTTP server listens on (the worker has no other HTTP surface, unlike the API, which serves `GET /metrics` itself). |
| `MINIO_ENDPOINT` | `zeroshield.repositories.minio_evidence_repository.default_minio_client` | `localhost:9000` | MinIO server host:port, only relevant if you construct a `MinioEvidenceRepository` yourself — no built-in interface uses MinIO by default. |
| `MINIO_ACCESS_KEY` | same | `zeroshield` | MinIO access key. |
| `MINIO_SECRET_KEY` | same | `zeroshield123` | MinIO secret key. |
| `MINIO_SECURE` | same | `false` | Set to `true` to connect over HTTPS. |
| `ZEROSHIELD_EVIDENCE_BACKEND` | `zeroshield.services.experiment_service._default_evidence_repository` | `local` | Selects which `EvidenceRepository` the API/worker/dashboard use for a run submitted through `experiment_service.run_experiment` (not the CLI, which always uses `LocalEvidenceRepository` directly — see below). `local` (default) uses `LocalEvidenceRepository`; `minio` uses `MinioEvidenceRepository` via `default_minio_client()`. `docker-compose.yml` sets this to `minio` for the `worker`/`dashboard` services (V2 Platform Foundation phase: MinIO is the intended primary evidence store for the containerised platform), while every bare-Python/CI/test invocation defaults to `local`, per V1 compatibility. |
| `MINIO_EVIDENCE_BUCKET` | same | `zeroshield-evidence` | Bucket name used when `ZEROSHIELD_EVIDENCE_BACKEND=minio`. |
| `DATABASE_URL` | API (`zeroshield.api.dependencies.get_run_repository`), worker (`zeroshield.worker.main.get_run_repository`), Alembic (`alembic/env.py` via `zeroshield.db.session.get_database_url`) | `postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield` | PostgreSQL connection string for the rich run-lifecycle event trail (`zeroshield.repositories.PostgresRunRepository`, `RunEventType`). If unset, the API/worker use the no-op `NullRunRepository` instead — Postgres is optional infrastructure, never a hard requirement to submit or process a run. `docker-compose.yml` sets this for `api`/`worker`. |
| `ZEROSHIELD_E2E_RABBITMQ_URL` | `tests/integration/test_api_worker_real_broker.py` only | *(none — no fallback)* | Opts into the one integration test that talks to a real RabbitMQ broker; deliberately has no default (see [`docs/TESTING.md`](TESTING.md#opting-into-the-real-broker-test)). |
| `ZEROSHIELD_E2E_POSTGRES_URL` | `tests/integration/test_worker_postgres_real_db.py` only | *(none — no fallback)* | Opts into the one integration test that runs the real Alembic migration and `PostgresRunRepository` against a real PostgreSQL database; deliberately has no default, mirroring `ZEROSHIELD_E2E_RABBITMQ_URL` (see [`docs/TESTING.md`](TESTING.md)). |
| `NVD_API_KEY` | `zeroshield.intelligence.connectors.nvd.NVDConnector` | *(none)* | Optional NVD API key (header `apiKey`), raising the rate limit from 5 to 50 requests/30s. Sync works without one, just slower. |
| `GITHUB_TOKEN` | `zeroshield.intelligence.connectors.github_advisory.GitHubAdvisoryConnector` | *(none)* | Optional GitHub token (`Authorization: Bearer`), raising the unauthenticated 60 requests/hour rate limit. |
| `AI_PROVIDER` | `zeroshield.ai.config.resolve_ai_provider` (called by `zeroshield.api.dependencies.get_ai_provider`) | *(unset → `NullAIProvider`)* | Selects the AI Research Analyst's provider (V2 Phase 5, Step 1). Only `anthropic` currently enables a real provider (`AnthropicProvider`); any other value, or unset, resolves to `NullAIProvider`, under which every `/analyst/*` and `/controls/*/regression/explain` route still returns a normal (503 `ai_unavailable`) response rather than failing — AI is never required for core validation execution. |
| `ANTHROPIC_API_KEY` | same | *(none)* | Required for `AI_PROVIDER=anthropic`. Missing it also degrades to `NullAIProvider` (logged at startup) rather than raising. |
| `AI_MODEL` | same | `claude-opus-5` | Overrides the Anthropic model ID `AnthropicProvider` calls. |
| `INTELLIGENCE_WORKER_METRICS_PORT` | intelligence-worker (`zeroshield.worker.intelligence_main.get_metrics_port`) | `9201` | Port the intelligence-worker's Prometheus metrics HTTP server listens on (V2 Phase 6, Step 5) — mirrors `WORKER_METRICS_PORT` for the run-job worker. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | API/worker/intelligence-worker (`zeroshield.observability.tracing.configure_tracing`) | *(unset → no exporter)* | Base URL of an OTLP/HTTP trace collector (Jaeger, Tempo, etc.) — `/v1/traces` is appended automatically. Unset by default so running the app or the test suite never requires a collector to be reachable. See [`docs/OBSERVABILITY.md`](OBSERVABILITY.md). |
| `ZEROSHIELD_TRACING_CONSOLE` | same | *(unset)* | Set to `1` to print spans to stdout as JSON — a local tracing debugging aid, ignored if `OTEL_EXPORTER_OTLP_ENDPOINT` is also set. |

None of these are required for local development without Docker/RabbitMQ/MinIO/PostgreSQL — the CLI, dashboard, and the synchronous parts of the API/tests all work with zero environment variables set (evidence defaults to local files, run-lifecycle events default to the no-op `NullRunRepository`).

## Optional dependency extras

Declared in `pyproject.toml`'s `[project.optional-dependencies]`. `pydantic` (core) is the only always-installed dependency; everything else is opt-in based on which interface(s) you're running.

| Extra | Installs | Needed for |
|---|---|---|
| `dashboard` | `streamlit` | Running the Streamlit dashboard. |
| `api` | `fastapi`, `uvicorn`, `prometheus-client`, `opentelemetry-*` | Running the FastAPI REST interface, including its Prometheus metrics and distributed tracing (V2 Phase 6, Step 5). |
| `queue` | `pika`, `prometheus-client`, `opentelemetry-*` | Running the worker/intelligence-worker processes / talking to RabbitMQ, including their metrics and tracing. |
| `storage` | `minio` | Constructing a `MinioEvidenceRepository` (never a hard dependency of any built-in interface — see `zeroshield/repositories/__init__.py`'s deliberate non-export). Required at runtime when `ZEROSHIELD_EVIDENCE_BACKEND=minio` is set. |
| `db` | `sqlalchemy`, `alembic`, `psycopg[binary]` | Constructing a `PostgresRunRepository`/`VulnerabilityRepository`, and running Alembic migrations. Required at runtime when `DATABASE_URL` is set. |
| `intelligence` | `httpx` | Running the NVD/CISA KEV/EPSS/GitHub Advisory connectors (`zeroshield.intelligence.connectors`) and the `/vulnerabilities`, `/priority-queue`, `/sources`, `/intelligence/*` API routes. |
| `excel` | `openpyxl` | Importing the CVE research workbook (`zeroshield.intelligence.excel_importer`). |
| `ai` | `anthropic` | Constructing a real `AnthropicProvider` (V2 Phase 5). Required at runtime when `AI_PROVIDER=anthropic` is set; without it, `AI_PROVIDER=anthropic` still degrades gracefully to `NullAIProvider` rather than crashing (`AnthropicProvider`'s SDK import is lazy). |
| `auth` | `argon2-cffi` | Password hashing/verification (V2 Phase 6) — required for the API to serve `/auth/login` or the CLI's `create-admin` at all; not optional the way `ai`/`storage` are, since every other route requires an authenticated session. |
| `observability` | `opentelemetry-api`, `opentelemetry-sdk`, `opentelemetry-instrumentation-fastapi`, `opentelemetry-exporter-otlp-proto-http` | A standalone install path for just the tracing pieces (V2 Phase 6, Step 5) — already included by `api`/`queue` above, so you don't need this separately for a normal install. |
| `dev` | `pytest`, `pytest-cov`, `ruff`, `mypy`, `httpx`, `pip-audit`, plus the `db`/`excel`/`auth`/`observability` extras' packages | Running tests, linting, type checking, and the dependency vulnerability scan. These packages are included directly (not just referenced) so the full test suite runs without a separate install step. |

Combine extras as needed, e.g. `pip install -e ".[api,queue,dev]"` for API + worker development. The CLI (`zeroshield` console script) itself needs no extras beyond the base install.

## Data/config directories (not environment variables)

These are plain paths resolved relative to the current working directory (`Path.cwd()` — see `get_experiments_dir`/`get_results_root`/`get_jobs_dir` across `zeroshield.api.dependencies` and `zeroshield.worker.main`), not configurable via environment variable:

| Directory | Contents |
|---|---|
| `experiments/` | `ExperimentDefinition` JSON files, auto-discovered by every interface. |
| `test_data/` | `TestSet` JSON dataset files referenced by experiments' `dataset_path`. |
| `results/` | Generated evidence (`<experiment_id>/<run_id>/manifest.json` + artefacts, `<experiment_id>/comparison.json`). |
| `jobs/` | Async job status records (`JOB-<uuid>.json`), the API/worker's bookkeeping side-channel — not a core SRS-traced entity. |
| `overleaf_exports/` | Generated Overleaf export files. |

## Docker Compose service credentials

Set in `docker-compose.yml`'s `environment:` blocks for the third-party
images — these are not read by any ZeroShield Python code directly (Python
code reads the `*_URL`/`MINIO_*` variables in the table above instead,
which `docker-compose.yml` populates using these same values). Each is
overridable via `.env` (see [`.env.example`](../.env.example)); every
default below works with no `.env` file at all (V2 Phase 6, Step 8 —
one-command release):

| Service | Variable | Default | Override via |
|---|---|---|---|
| `postgres` | `POSTGRES_PASSWORD` | `zeroshield123` | `.env`'s `POSTGRES_PASSWORD` |
| `minio` | `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | `zeroshield` / `zeroshield123` (matches `MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY` defaults above, so the out-of-the-box MinIO client config just works) | `.env`'s `MINIO_ROOT_PASSWORD` |
| `grafana` | `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` | `zeroshield` / `zeroshield123` | `.env`'s `GRAFANA_ADMIN_PASSWORD` |

Host ports are deliberately remapped away from each service's usual default (RabbitMQ AMQP on `5673` not `5672`, MinIO on `9002`/`9003` not `9000`/`9001`, dashboard on `8502` not `8501`) so `docker compose up` doesn't collide with an unrelated instance of the same software already running on the host. See the comments at the top of `docker-compose.yml` for the incident that made this a hard rule, and [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) for the full host-port table and first-time (`create-admin`) setup steps.
