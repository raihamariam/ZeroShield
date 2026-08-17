# ZeroShield — Handover Guide

This is the project's formal handover document, per the SRS closeout criteria (§18, Definition of Done: "A handover guide explains setup, execution, extension and safety controls"). It is written for someone who has never seen this codebase before — a new researcher, a reviewer, or a future maintainer — and needs to understand what ZeroShield is, how to run it, how to extend it, and what keeps it safe.

For step-by-step, copy-pasteable walkthroughs of the dashboard, API, and Docker setup, see the main [README](../README.md). This document is the narrower "how does the whole thing fit together and how do I extend it safely" companion to that.

## 1. What ZeroShield is

ZeroShield is a defensive R&D prototype that converts selected VPN and Telecommunications zero-click CVE research into safe, reproducible, **synthetic** mitigation-validation experiments. For a given documented failure pattern (e.g. a pre-authentication parsing flaw), ZeroShield runs the *same* synthetic test set through a **baseline** (weak/vulnerable-shaped) processing strategy and a **mitigation** (hardened) processing strategy, records what each one did case-by-case, and produces a factual, hash-verified evidence bundle comparing the two. It never targets real systems, never uses live exploit payloads, and never touches production infrastructure — see §5 (Safety controls) below.

Authoritative requirements source: `ZC_Mitigation_Validation_Framework_SRS.docx` (draft, pending supervisor approval).

## 2. Setup

Requires Python 3.12+ and (optionally) Docker Desktop.

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Install additional extras depending on which interface(s) you need — see the table in [`docs/CONFIGURATION.md`](CONFIGURATION.md#optional-dependency-extras). A fresh checkout can be fully set up and exercised using only the commands in this document and the README — no undocumented steps (SRS NFR-009).

Verify the install:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## 3. Execution

ZeroShield has four interfaces over the same underlying engine (`zeroshield.services.experiment_service` and `zeroshield.orchestration`) — none of them duplicate business logic, they are all thin wrappers:

| Interface | Use it for | Where to start |
|---|---|---|
| CLI (`zeroshield`) | Scripted/local single-run use, evidence verification | [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) |
| Dashboard (Streamlit) | Interactive, non-technical demonstration | [README § Running the ZeroShield Dashboard](../README.md#running-the-zeroshield-dashboard) |
| API (FastAPI) | Programmatic/remote access, async execution | [README § Running the ZeroShield API](../README.md#running-the-zeroshield-api) |
| Docker Compose | Everything at once, zero local Python setup | [README § Running ZeroShield with Docker](../README.md#running-zeroshield-with-docker) |

A run always produces the same evidence shape regardless of which interface triggered it: a `manifest.json` (hashed, integrity-checkable), the run's raw artefacts, and — once both baseline and mitigation have run — a `comparison.json` under `results/<experiment_id>/`.

## 4. Extension

### Adding a new experiment

Drop a new `*.json` file into `experiments/` that validates against `zeroshield.models.ExperimentDefinition`. It is picked up automatically by every interface — nothing is hard-coded to `ZC-VPN-EXP-001`/`ZC-TELECOM-EXP-001` (see `zeroshield.experiments.discovery.discover_experiments`). A new experiment needs:

- A `dataset_path` pointing at a `TestSet`-shaped JSON file (see existing files under `test_data/` for the shape).
- `baseline_strategy` / `mitigation_strategy` identifiers that resolve via the strategy registry (see below) — either reuse existing ones or register new ones.
- `approval_status: "draft"` until a reviewer approves it; `experiment_run` execution context refuses anything not `"approved"` (SAFE-004) — use `local_unit_test` to exercise a draft experiment locally.

Run `zeroshield validate-experiment <path>` (see [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md)) to check schema, dataset availability, and safety policy before attempting a real run.

### Adding a new baseline/mitigation strategy

Implement `zeroshield.strategies.base.ProcessingStrategy` (one method: `process(self, input_data: dict) -> StrategyOutcome`, plus a class-level `strategy_id`), then register the class in `zeroshield.strategies.registry._REGISTRY`. This is the Strategy + Registry pattern (SRS §4.2) — `resolve_strategy(strategy_id)` is the only way runner code ever obtains a strategy instance, so a new strategy needs no other code changes to become runnable by every interface.

### Adding a new evidence storage backend

Implement `zeroshield.repositories.evidence_repository.EvidenceRepository` (`save_run_evidence`, `load_manifest`, `save_comparison`) — see `LocalEvidenceRepository` (default) and `MinioEvidenceRepository` (optional, `storage` extra) for reference implementations. `zeroshield.orchestration.execute_and_generate_evidence` depends only on the ABC, never a concrete class, so a new backend needs no orchestration changes. Which backend is selected by default is controlled by `ZEROSHIELD_EVIDENCE_BACKEND` (`local`, the default, or `minio`) — see [`docs/CONFIGURATION.md`](CONFIGURATION.md).

### The run-lifecycle system of record (V2 Platform Foundation)

Every async run submitted via `POST /experiments/{id}/runs` now also records a rich lifecycle trail through `zeroshield.repositories.RunRepository` — `QUEUED` (API, best-effort) through `PREPARING`/`SAFETY_CHECK`/`RUNNING_BASELINE`/`RUNNING_MITIGATION`/`ANALYSING`/`GENERATING_EVIDENCE`/`COMPLETED` (worker, emitted from the real execution path via an `event_sink` callback threaded through `ExperimentRunner.run()` → `execute_and_generate_evidence()` → `experiment_service.run_experiment()`), or `DENIED`/`FAILED`. This is additive to, not a replacement for, the existing `JobStore` file-based job status API clients poll via `GET /jobs/{job_id}` — that contract is unchanged.

`RunRepository` defaults to `NullRunRepository` (a no-op) unless `DATABASE_URL` is set, in which case `PostgresRunRepository` (requires the `db` extra: `sqlalchemy`, `alembic`, `psycopg`) persists events to PostgreSQL. Apply the schema with:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m alembic upgrade head
```

A `RunRepository` failure (e.g. Postgres unreachable) is always caught and logged — it can never block or alter job submission/processing, since it is auxiliary observability, never a safety authority. See [`docs/ARCHITECTURE.md` §6a](ARCHITECTURE.md#6a-v2-platform-foundation-postgresql-run-lifecycle-system-of-record).

### Threat Intelligence & Prioritisation (V2 Phase 2)

`GET /vulnerabilities`, `GET /priority-queue`, `GET /sources`/`/integrations`, and `POST /intelligence/sync` (+ `GET /intelligence/syncs[/​{sync_id}]`) automate CVE research from NVD, CISA KEV, FIRST EPSS, and GitHub Security Advisories into a deterministic, explainable ZeroShield Validation Priority and VPN/Telecom `ValidationCandidate` records — replacing the manual CVE-to-Excel-to-experiment workflow. No AI is involved anywhere in this pipeline.

Unlike `RunRepository`, `DATABASE_URL` is **required** for every intelligence route/worker (503 without it) — PostgreSQL is the system of record here (Step 1 of the phase), not optional auxiliary observability. Apply the schema and try a sync:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[api,intelligence,db,dev]"
$env:DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn zeroshield.api.app:app --reload
# in another terminal:
.\.venv\Scripts\python.exe -m pip install -e ".[queue,intelligence,db]"
.\.venv\Scripts\python.exe -m zeroshield.worker.intelligence_main
```

Then `POST /intelligence/sync` with `{"source": "cisa_kev"}` in Swagger and poll `GET /intelligence/syncs/{sync_id}`. The existing research workbook (`telecom_vpn_cve_zero_click.xlsx`) remains importable via `zeroshield.intelligence.excel_importer.import_and_merge()` — it never creates, modifies, or runs an `ExperimentDefinition`. See [`docs/ARCHITECTURE.md` §6b](ARCHITECTURE.md#6b-v2-phase-2-threat-intelligence--prioritisation) for the full design, and the Phase 2 Completion Report for connector/scoring details and known limitations.

### Advanced Validation Platform (V2 Phase 3)

Researchers can now build a VPN or Telecom experiment through `POST /experiment-versions` (Domain Pack + Validation Template + a deterministic generator config) instead of hand-authoring an experiment JSON file. The workflow: create a DRAFT → `submit-review` → `start-review` → `approve` (or `reject`) → `POST /experiment-versions/{id}/runs` (only once `APPROVED`) → poll the job the same way as any other run → `GET /experiments/{id}/verdict` for a deterministic, threshold-based outcome. Approval never bypasses `SafetyPolicy` - it only sets `ExperimentVersion.definition.approval_status` in lockstep with the workflow state, and the real, unmodified `SafetyPolicy.evaluate()` still runs at execution time, every time.

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[api,db,dev]"
$env:DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn zeroshield.api.app:app --reload
```

Try `GET /domain-packs` and `GET /domain-packs/vpn/templates` in Swagger first to see what's available, then `POST /datasets/generate` to preview a synthetic dataset before committing to a draft. See [`docs/ARCHITECTURE.md` §6c](ARCHITECTURE.md#6c-v2-phase-3-advanced-validation-platform) for the full design, and the Phase 3 Completion Report for the approval state machine, sandbox controls, verdict thresholds, and known limitations.

### AI Research Analyst & Continuous Assurance (V2 Phase 5)

ZeroShield now accumulates knowledge over time instead of only running isolated experiments: an advisory-only AI Research Analyst (CVE explanation, failure-pattern classification, mitigation-gap analysis, similarity narration, template recommendation, draft experiment proposals), deterministic CVE correlation, a small asset inventory, a Control/ControlVersion/ControlValidation model with effectiveness aggregation, deterministic regression detection, and a human-reviewed revalidation queue. **AI is advisory only, everywhere** - it cannot approve experiments, bypass `SafetyPolicy`, modify evidence, execute code, or change a verdict; see [`docs/ARCHITECTURE.md` §6d](ARCHITECTURE.md#6d-v2-phase-5-ai--continuous-assurance) for the full design and the Phase 5 Completion Report for the AI safety-boundary tests.

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[api,db,ai,dev]"
$env:DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m alembic upgrade head
# optional - AI features work fully without this; every /analyst/* route
# just answers 503 "ai_unavailable" instead, with no other effect:
$env:AI_PROVIDER = "anthropic"
$env:ANTHROPIC_API_KEY = "sk-ant-..."
.\.venv\Scripts\python.exe -m uvicorn zeroshield.api.app:app --reload
```

Try `POST /vulnerabilities/{cve_id}/analyst/mitigation-gap` and `GET /vulnerabilities/{cve_id}/correlations` in Swagger, then `GET /ai-assessments` to see the persisted, `reviewed=False` result - only `POST /ai-assessments/{id}/review` marks it reviewed, never any automatic process. `POST /revalidation/scan` runs the deterministic trigger scan; `GET /controls/{id}/effectiveness` shows the aggregated trend plus a regression banner once ≥2 same-version validations exist. The `apps/web` Next.js UI (V2 Phase 4's application shell) surfaces all of this on the vulnerability, Assets, Controls, and Revalidation pages, plus a "new critical AI assessments / active regressions / pending revalidations" summary on Mission Control.

### Local Authentication, RBAC, Audit, and Observability (V2 Phase 6)

Every route except `GET /health`, `GET /metrics`, and `POST /auth/login`
now requires an authenticated session - Argon2id-hashed passwords, opaque
server-side sessions, account lockout, four roles
(`viewer`/`researcher`/`reviewer`/`admin`) enforced per-route server-side,
and a REVIEWER/RESEARCHER can never approve their own experiment version
(ADMIN is an explicit override). Every security-relevant action is recorded
in an append-only audit trail viewable at `/audit-trail` (ADMIN-only). See
[`docs/SECURITY.md`](SECURITY.md) for the full model and the RBAC matrix.

There is no seeded account - bootstrap the first ADMIN before doing
anything else:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[api,db,auth,dev]"
$env:DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\zeroshield.exe create-admin --username alice --password "a strong password, 12+ chars"
```

Then sign in at the web app's `/login` page. Everyone else (RESEARCHER,
REVIEWER, more ADMINs) is created from the Users page by an existing ADMIN.

Phase 6 also added structured JSON logging, a `request_id`/`trace_id`
correlated across every log line and audit row for one request, and
OpenTelemetry distributed tracing across the browser → API → RabbitMQ →
worker hop (no exporter configured by default - spans are created but
inert unless `OTEL_EXPORTER_OTLP_ENDPOINT` or `ZEROSHIELD_TRACING_CONSOLE=1`
is set). See [`docs/OBSERVABILITY.md`](OBSERVABILITY.md).

## 5. Safety controls

Every experiment run — regardless of interface — is evaluated by `SafetyPolicy` (`zeroshield.policies`) before execution. This is policy-as-code, not a convention: refusal is enforced in code, not by operator discipline. Implemented rules (SRS §10.1):

| Rule | Enforces |
|---|---|
| SAFE-001 | `external_targeting` must be `false` — no real-system targeting exists in Phase 1. |
| SAFE-002 | `SYNTHETIC_ONLY` safety level requires `synthetic` input classification. |
| SAFE-003 | `weaponised_payloads` must be `false`. |
| SAFE-004 | Experiments must be `approved` before running outside `local_unit_test` context. |
| SAFE-006 | Static scan of checked-in `experiments/`/`test_data/` JSON rejects secret-shaped strings (`tests/security/test_static_analysis_guards.py`). |

SAFE-005, SAFE-007 and SAFE-008 are specified in the SRS but **not fully implemented** — SAFE-008's rejection path works but isn't uniformly logged across every interface, and SAFE-005/007 have no code at all yet. See [`docs/TRACEABILITY.md` §4](TRACEABILITY.md#4-safety--policy-as-code-rules-§101) (Milestone 30) for the precise, verified status of each, and [`docs/TESTING.md` § Known gaps](TESTING.md#known-gaps-not-covered-by-this-suite) for what SAFE-005 would require and why it's deferred.

Additional structural safety properties, not policy rules but enforced in code and covered by `tests/security/` (Milestone 26):

- **Evidence immutability** — a run's evidence, once written, can never be silently overwritten (`EvidenceAlreadyExistsError`).
- **Path-traversal resistance** — every user-facing identifier (`experiment_id`, `run_id`, `job_id`) is resolved by equality-comparison against already-discovered, already-validated values, never used to build a filesystem path directly from untrusted input.
- **Queue message robustness** — a malformed or adversarial RabbitMQ message is logged and dropped, never able to crash the worker process.

Two `execution_context` values gate what a run is allowed to do, independent of the SAFE-* rules above: `local_unit_test` (draft experiments allowed, for local development/demonstration) and `experiment_run` (the real/reviewed path — requires `approved` status).

## 6. Where to look next

- [`docs/DEMONSTRATION.md`](DEMONSTRATION.md) — a ~10-minute guided walkthrough for showing ZeroShield to a supervisor/reviewer, including a live reproducibility check.
- [`docs/SECURITY.md`](SECURITY.md) — authentication, RBAC, self-approval blocking, the audit trail, and the security test suite (V2 Phase 6).
- [`docs/OBSERVABILITY.md`](OBSERVABILITY.md) — Prometheus metrics, structured JSON logging, and distributed tracing (V2 Phase 6).
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — CI and the finalized one-command Docker Compose release (V2 Phase 6).
- [`docs/FUTURE_OPPORTUNITIES.md`](FUTURE_OPPORTUNITIES.md) — documentation-only notes on cloud/Kubernetes/SaaS/SSO directions, deliberately not implemented.
- [`docs/TRACEABILITY.md`](TRACEABILITY.md) — the Milestone 30 requirement-by-requirement SRS compliance review (every `FR-*`/`NFR-*`/`SAFE-*`/`AC-*`, D-05's resolution) — read this for what is and isn't actually done, verified against code rather than claimed. Predates V2 Phase 1-6 and is left as the historical Milestone 30 snapshot rather than rewritten.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — the seven-layer logical architecture, design patterns, and diagrams (component, deployment, run-flow sequences) behind everything described above.
- [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) — every CLI command and its arguments.
- [`docs/CONFIGURATION.md`](CONFIGURATION.md) — every environment variable and dependency extra.
- [`docs/TESTING.md`](TESTING.md) — how to run and interpret the test suite, including the security suite and known gaps.
- [README](../README.md) — dashboard/API/Docker/MinIO/Prometheus walkthroughs.
- `ZC_Mitigation_Validation_Framework_SRS.docx` — the authoritative requirements source; every `FR-*`/`NFR-*`/`SAFE-*`/`AC-*` identifier referenced in code and tests traces back to it.

### A note on the legacy Streamlit dashboard

Kept for this release (still read-only, still incapable of bypassing the
web app's governed workflow - see [`docs/SECURITY.md` §6](SECURITY.md#6-what-phase-6-deliberately-left-alone)),
but the Next.js web app (`apps/web/`) has been the primary interface since
Phase 4 and is the only one with authentication. A future maintainer should
consider retiring the dashboard outright once nobody depends on it - it
duplicates functionality the web app already covers better, and its lack
of a session/RBAC model is a permanent asterisk on an otherwise fully
governed system, even though it is not itself an exploitable gap today.
