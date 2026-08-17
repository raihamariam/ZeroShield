# ZeroShield CLI Reference

The `zeroshield` command-line tool (installed as a console script by `pip install -e .`) is a thin interface over the same engine the dashboard/API/worker use — it implements no business logic of its own (`zeroshield.cli.commands`, per the thin-interface-layer pattern used throughout this project).

```powershell
.\.venv\Scripts\zeroshield.exe --help
```

(or, without activating/using the console script directly: `.\.venv\Scripts\python.exe -c "from zeroshield.cli import main; main()" --help`.)

Every command exits `0` on success and `1` on failure (schema/dataset/safety failure, or a `CliError`), so it composes normally in scripts (`if ($LASTEXITCODE -ne 0) { ... }`).

## `validate-experiment`

Load, schema-validate, and safety-evaluate an experiment definition **without executing it**. Use this before `run` to check what will happen.

```powershell
zeroshield validate-experiment experiments\ZC-VPN-EXP-001.json --context local_unit_test
```

| Argument | Required | Meaning |
|---|---|---|
| `experiment_path` | yes | Path to an `ExperimentDefinition` JSON file. |
| `--context` | no | `local_unit_test` or `experiment_run` (default: `experiment_run`). See [`docs/HANDOVER.md` § Safety controls](HANDOVER.md#5-safety-controls). |

Reports: schema validation, dataset file presence, and every `SAFE-*` policy check result with its reason if refused.

## `run`

Execute an experiment's baseline **and** mitigation strategies against its dataset, generate evidence, and write it to disk. Refuses to run (exit `1`, no evidence written) if the safety policy denies it — the check happens before any case is processed.

```powershell
zeroshield run experiments\ZC-VPN-EXP-001.json --context local_unit_test
```

| Argument | Required | Meaning |
|---|---|---|
| `experiment_path` | yes | Path to an `ExperimentDefinition` JSON file. |
| `--context` | no | `local_unit_test` or `experiment_run` (default: `experiment_run`). |
| `--baseline-run-id` | no | Override the auto-generated baseline run ID (default: `RUN-<unix-timestamp>01`). |
| `--mitigation-run-id` | no | Override the auto-generated mitigation run ID (default: `RUN-<unix-timestamp>02`). |
| `--git-commit` | no | Hex commit reference recorded in evidence (default: `0000000` placeholder). |
| `--results-dir` | no | Root directory evidence is written under (default: `results`). |

Prints case counts, both runs' statuses, key metrics (block rate, valid-acceptance rate, block-rate improvement), and the evidence output path on success.

## `compare`

Display an **already-generated** `comparison.json` for an experiment. Never re-runs anything — read-only.

```powershell
zeroshield compare results\ZC-VPN-EXP-001
```

| Argument | Required | Meaning |
|---|---|---|
| `experiment_dir` | yes | e.g. `results\ZC-VPN-EXP-001` (must contain `comparison.json`, written by a prior `run`). |

Prints a per-metric baseline-vs-mitigation-vs-difference table, block-rate improvement, latency overhead, and the recorded limitations.

## `verify-evidence`

Load a single run's `manifest.json` and verify artefact presence plus the manifest's integrity hash (SHA-256 over the manifest's own content, tamper-evident — see `zeroshield.repositories.verify_manifest_integrity`).

```powershell
zeroshield verify-evidence results\ZC-VPN-EXP-001\RUN-1234567890
```

| Argument | Required | Meaning |
|---|---|---|
| `run_dir` | yes | A single run's directory, e.g. `results\ZC-VPN-EXP-001\RUN-1234567890` (not the experiment-level directory `compare` uses). |

This command takes a local filesystem path the operator explicitly points it at, like `cat`; it is not a network-facing or otherwise untrusted-input command, unlike the API's `experiment_id`/`job_id` path parameters (see `tests/security/test_path_traversal_comprehensive.py`).

## `create-admin`

Bootstrap the first ADMIN user (V2 Phase 6). There is no seeded/default
account - this is the only way to get the first login. Requires
`DATABASE_URL` (auth is PostgreSQL-backed, not optional). Run once per
fresh database; running it again just creates another ADMIN.

```powershell
zeroshield create-admin --username alice --password "a strong password, 12+ characters"
```

| Argument | Required | Meaning |
|---|---|---|
| `--username` | yes | The new ADMIN's username. |
| `--password` | no | Must be at least 12 characters if given. Omit it to have a strong random password generated and printed **once** - it is hashed (Argon2id) and never stored or logged anywhere in recoverable form, so write it down immediately. |

Records `Action.USER_CREATED` in the audit trail with
`actor_username="cli:create-admin"`, so a bootstrap admin is distinguishable
from one created later via the web app's Users page by an existing ADMIN.
See [`docs/SECURITY.md`](SECURITY.md) for the full auth/RBAC model and every
other role (`viewer`/`researcher`/`reviewer`), which are created from the
Users page (ADMIN-only) once the first ADMIN exists.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Command completed successfully (for `run`: safety policy allowed and execution completed; for `validate-experiment`: overall validation passed). |
| `1` | A `CliError` (file not found, invalid JSON, schema validation failure, unknown strategy, missing dataset) — printed to stderr as `ERROR: ...` — or, for `run`, a safety-policy refusal. |
