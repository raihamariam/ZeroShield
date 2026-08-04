# ZeroShield Testing Guide

## Running the suite

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Runs the full suite with **no external services required** — 559+ tests, no Docker/RabbitMQ/MinIO needed (async/queue tests use a fake in-process publisher, exactly as the API does when tested). With coverage:

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
| `tests/unit/` | One subdirectory per `src/zeroshield` package (`models`, `strategies`, `runners`, `services`, `repositories`, `api`, `cli`, `dashboard`, `worker`, ...) — fast, isolated, no real external services. |
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

## Known gaps (not covered by this suite)

Documented explicitly rather than silently absent, per this project's practice of stating pending/deferred work rather than implying completeness:

- **SAFE-005** (network egress denied by default for sandbox containers) — no sandbox container execution exists in this codebase yet to test against; this is infrastructure/design work for a future milestone, not something an automated test can retrofit onto nothing.
- **Cryptographic queue-payload signing** — the SRS's §10.3 "signed/validated payloads" threat-model line is currently satisfied by schema validation only (`RunJobMessage.model_validate_json`, `extra="forbid"`, enforced by `handle_message_body`). Message-level signing would be a design addition to the queue producer/consumer, not a test.
- **Docker-container-level regression checks** are performed manually (see the Milestone 26 report/commit for the exact procedure: real malformed messages published directly to a real running worker container, confirmed dropped without a crash) rather than as an automated `pytest` test, since they require a live Docker daemon the rest of the suite deliberately does not depend on.
