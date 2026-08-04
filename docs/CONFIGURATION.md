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
| `ZEROSHIELD_E2E_RABBITMQ_URL` | `tests/integration/test_api_worker_real_broker.py` only | *(none — no fallback)* | Opts into the one integration test that talks to a real RabbitMQ broker; deliberately has no default (see [`docs/TESTING.md`](TESTING.md#opting-into-the-real-broker-test)). |

None of these are required for local development without Docker/RabbitMQ/MinIO — the CLI, dashboard, and the synchronous parts of the API/tests all work with zero environment variables set.

## Optional dependency extras

Declared in `pyproject.toml`'s `[project.optional-dependencies]`. `pydantic` (core) is the only always-installed dependency; everything else is opt-in based on which interface(s) you're running.

| Extra | Installs | Needed for |
|---|---|---|
| `dashboard` | `streamlit` | Running the Streamlit dashboard. |
| `api` | `fastapi`, `uvicorn`, `prometheus-client` | Running the FastAPI REST interface. |
| `queue` | `pika`, `prometheus-client` | Running the worker process / talking to RabbitMQ. |
| `storage` | `minio` | Constructing a `MinioEvidenceRepository` (never a hard dependency of any built-in interface — see `zeroshield/repositories/__init__.py`'s deliberate non-export). |
| `dev` | `pytest`, `pytest-cov`, `ruff`, `mypy`, `httpx`, `pip-audit` | Running tests, linting, type checking, and the dependency vulnerability scan. |

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

Set directly in `docker-compose.yml`'s `environment:` blocks for the third-party images — these are not read by any ZeroShield Python code:

| Service | Variables | Default |
|---|---|---|
| `minio` | `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | `zeroshield` / `zeroshield123` (matches `MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY` defaults above, so the out-of-the-box MinIO client config just works). |
| `grafana` | `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` | `zeroshield` / `zeroshield123`. |

Host ports are deliberately remapped away from each service's usual default (RabbitMQ AMQP on `5673` not `5672`, MinIO on `9002`/`9003` not `9000`/`9001`, dashboard on `8502` not `8501`) so `docker compose up` doesn't collide with an unrelated instance of the same software already running on the host. See the comments at the top of `docker-compose.yml` for the incident that made this a hard rule.
