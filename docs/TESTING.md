# ZeroShield Testing Guide

## Running the suite

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Runs the full suite with **no external services required** — 857+ tests, no Docker/RabbitMQ/MinIO/PostgreSQL/live-network needed (async/queue tests use a fake in-process publisher, exactly as the API does when tested; `PostgresRunRepository`/`VulnerabilityRepository`/`ExperimentVersionRepository` tests use an in-memory SQLite engine; connector tests use `httpx.MockTransport` fixtures). With coverage:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --cov
```

Coverage is configured (`[tool.coverage.run]` in `pyproject.toml`) against `src/zeroshield`, excluding `__main__.py` entry points and the dashboard's top-level Streamlit script (not meaningfully unit-testable — exercised instead by `tests/integration/test_dashboard_full_workflow.py`'s real headless rendering).

Lint and type-check:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
```

`mypy` is scoped to `src/` only (strict mode: `disallow_untyped_defs = true`); tests are not type-checked.

## Directory layout

| Directory | What it covers |
|---|---|
| `tests/unit/` | One subdirectory per `src/zeroshield` package (`models`, `strategies`, `runners`, `services`, `repositories`, `api`, `cli`, `dashboard`, `worker`, `db`, `intelligence`, ...) — fast, isolated, no real external services. `repositories/test_run_repository.py` and `intelligence/test_repository.py` exercise their Postgres-backed repositories against an in-memory SQLite engine, not a live Postgres; `intelligence/connectors/` uses `httpx.MockTransport` fixtures instead of live network. |
| `tests/policy/` | `SafetyPolicy` and individual `SAFE-*` rules in isolation. |
| `tests/experiments/` | Fixture experiment definition files (`valid_experiment_example.json`, `invalid_experiment_example.json`) used by model/discovery tests — not itself a test module. |
| `tests/integration/` | Cross-process, real-interface end-to-end tests: real CLI subprocess, real headless Streamlit rendering, and (opt-in only) a real RabbitMQ broker. See below. |
| `tests/security/` | Milestone 26's dedicated security/failure-path suite — see below. |

## The security suite (`tests/security/`)

| File | Covers |
|---|---|
| `test_evidence_immutability.py` | A run's evidence can never be silently overwritten (`EvidenceAlreadyExistsError`), in both `LocalEvidenceRepository` and `MinioEvidenceRepository`. |
| `test_queue_message_robustness.py` | The worker's `handle_message_body()` never raises for any malformed/adversarial message body (empty, non-JSON, missing fields, invalid enum, embedded NUL byte, binary garbage, oversized payload) — and still processes a genuinely valid message correctly. |
| `test_path_traversal_comprehensive.py` | Every id-accepting API route rejects a shared list of malicious ids without leaking anything outside the sanctioned `results_root`/`jobs_dir`/`experiments_dir`. |
| `test_static_analysis_guards.py` | SAFE-006: no secret-shaped strings in checked-in `experiments/`/`test_data/` JSON. AC-09: no dangerous execution primitive (`eval`/`exec`/`os.system`/`subprocess(shell=True)`/`pickle`/`__import__`) anywhere in `src/`, without a reviewed allowlist entry. |
| `test_dependency_vulnerabilities.py` | Runs the real `pip-audit` CLI against installed dependencies; skips (not fails) if outbound network access to the advisory database is unavailable. |

Run just this suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/security
```

## Opting into the real-broker test

`tests/integration/test_api_worker_real_broker.py` publishes to and consumes from a **real** RabbitMQ broker instead of a fake, proving the actual message-queue mechanics work end-to-end. It is skipped by default, and **deliberately has no default host/port to fall back to** — read `ZEROSHIELD_E2E_RABBITMQ_URL` only. An earlier version defaulted to `localhost:5672` and silently connected to a completely unrelated RabbitMQ container from another project that happened to already be using that port on the development machine.

```powershell
docker compose up -d rabbitmq
$env:ZEROSHIELD_E2E_RABBITMQ_URL = "amqp://guest:guest@localhost:5673/"
.\.venv\Scripts\python.exe -m pytest tests/integration/test_api_worker_real_broker.py
```

Note port `5673`, not RabbitMQ's default `5672` — see `docker-compose.yml`'s comments and [`docs/CONFIGURATION.md`](CONFIGURATION.md) for why.

## Opting into the real-Postgres migration/run-lifecycle test

`tests/integration/test_worker_postgres_real_db.py` (V2 Platform Foundation phase) runs the real Alembic migration and `PostgresRunRepository` against a **real** PostgreSQL database instead of the in-memory SQLite used by `tests/unit/repositories/test_run_repository.py`. Skipped by default, deliberately has no default host/port to fall back to, for the same reason as the real-broker test above:

```powershell
docker compose up -d postgres
$env:ZEROSHIELD_E2E_POSTGRES_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m pytest tests/integration/test_worker_postgres_real_db.py
```

## Threat Intelligence & Prioritisation tests (`tests/unit/intelligence/`, V2 Phase 2)

Connectors (`tests/unit/intelligence/connectors/`) are tested against `httpx.MockTransport` with fixtures shaped exactly like the official NVD/CISA KEV/FIRST EPSS/GitHub Advisories responses read at implementation time — no live network access, per the phase's own requirement ("do not make CI depend on live internet"). `normalisation`/`dedup`/`priority`/`candidates`/`repository`/`sync_service`/`excel_importer` are tested directly against real logic (in-memory SQLite for the repository, like `tests/unit/repositories/test_run_repository.py`), covering malformed/partial upstream data, merge conflict rules, deterministic priority scoring and explanations, and the `RunRepository`-style failure-isolation guarantee (a `RunRepository`/connector failure never corrupts or blocks sync bookkeeping). No opt-in real-network integration test exists for these connectors, unlike RabbitMQ/Postgres above — intentional, per the phase's mocked-fixtures-only instruction.

## Advanced Validation Platform tests (`tests/unit/domain_packs/`, `tests/unit/templates/`, `tests/unit/generators/`, `tests/unit/sandbox/`, `tests/unit/verdict/`, `tests/unit/studio/`, V2 Phase 3)

Domain Pack/template registration and unknown-id rejection; deterministic dataset generation (same seed+config → byte-identical SHA-256) verified against the *real* strategies (every generated case's `expected_outcome` is checked against what `StrictSchemaCanonicalisationMitigation`/`StrictGrammarStateMachineMitigation` actually decide, not asserted independently); the full approval state machine including every illegal-transition/bypass-attempt combination and an explicit proof that an approved version is still independently evaluated by the real `SafetyPolicy`; sandbox timeout/network-guard/allow-list/workspace-cleanup (including cleanup-on-exception); verdict thresholds for all five labels plus incomplete-metrics and regression-vs-previous-run cases; and `tests/unit/studio/test_studio_migration.py`, which builds Domain-Pack/template-based equivalents of `ZC-VPN-EXP-001`/`ZC-TELECOM-EXP-001` and runs both old and new through the identical, unmodified trusted core (Step 9).

## Known gaps (not covered by this suite)

Documented explicitly rather than silently absent, per this project's practice of stating pending/deferred work rather than implying completeness:

- **SAFE-005** (network egress denied by default for sandbox containers) — no sandbox container execution exists in this codebase yet to test against; this is infrastructure/design work for a future milestone, not something an automated test can retrofit onto nothing.
- **Cryptographic queue-payload signing** — the SRS's §10.3 "signed/validated payloads" threat-model line is currently satisfied by schema validation only (`RunJobMessage.model_validate_json`, `extra="forbid"`, enforced by `handle_message_body`). Message-level signing would be a design addition to the queue producer/consumer, not a test.
- **Docker-container-level regression checks** are performed manually (see the Milestone 26 report/commit for the exact procedure: real malformed messages published directly to a real running worker container, confirmed dropped without a crash) rather than as an automated `pytest` test, since they require a live Docker daemon the rest of the suite deliberately does not depend on.
