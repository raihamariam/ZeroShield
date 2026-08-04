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

Implement `zeroshield.repositories.evidence_repository.EvidenceRepository` (`save_run_evidence`, `load_manifest`, `save_comparison`) — see `LocalEvidenceRepository` (default) and `MinioEvidenceRepository` (optional, `storage` extra) for reference implementations. `zeroshield.orchestration.execute_and_generate_evidence` depends only on the ABC, never a concrete class, so a new backend needs no orchestration changes.

## 5. Safety controls

Every experiment run — regardless of interface — is evaluated by `SafetyPolicy` (`zeroshield.policies`) before execution. This is policy-as-code, not a convention: refusal is enforced in code, not by operator discipline. Implemented rules (SRS §10.1):

| Rule | Enforces |
|---|---|
| SAFE-001 | `external_targeting` must be `false` — no real-system targeting exists in Phase 1. |
| SAFE-002 | `SYNTHETIC_ONLY` safety level requires `synthetic` input classification. |
| SAFE-003 | `weaponised_payloads` must be `false`. |
| SAFE-004 | Experiments must be `approved` before running outside `local_unit_test` context. |

SAFE-005 through SAFE-008 are specified in the SRS but **not yet implemented** — see [`docs/TESTING.md` § Known gaps](TESTING.md#known-gaps-not-covered-by-this-suite) for what each would require and why they're deferred.

Additional structural safety properties, not policy rules but enforced in code and covered by `tests/security/` (Milestone 26):

- **Evidence immutability** — a run's evidence, once written, can never be silently overwritten (`EvidenceAlreadyExistsError`).
- **Path-traversal resistance** — every user-facing identifier (`experiment_id`, `run_id`, `job_id`) is resolved by equality-comparison against already-discovered, already-validated values, never used to build a filesystem path directly from untrusted input.
- **Queue message robustness** — a malformed or adversarial RabbitMQ message is logged and dropped, never able to crash the worker process.

Two `execution_context` values gate what a run is allowed to do, independent of the SAFE-* rules above: `local_unit_test` (draft experiments allowed, for local development/demonstration) and `experiment_run` (the real/reviewed path — requires `approved` status).

## 6. Where to look next

- [`docs/DEMONSTRATION.md`](DEMONSTRATION.md) — a ~10-minute guided walkthrough for showing ZeroShield to a supervisor/reviewer, including a live reproducibility check.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — the seven-layer logical architecture, design patterns, and diagrams (component, deployment, run-flow sequences) behind everything described above.
- [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) — every CLI command and its arguments.
- [`docs/CONFIGURATION.md`](CONFIGURATION.md) — every environment variable and dependency extra.
- [`docs/TESTING.md`](TESTING.md) — how to run and interpret the test suite, including the security suite and known gaps.
- [README](../README.md) — dashboard/API/Docker/MinIO/Prometheus walkthroughs.
- `ZC_Mitigation_Validation_Framework_SRS.docx` — the authoritative requirements source; every `FR-*`/`NFR-*`/`SAFE-*`/`AC-*` identifier referenced in code and tests traces back to it.
