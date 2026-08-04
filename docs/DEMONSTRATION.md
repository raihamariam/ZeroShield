# ZeroShield Demonstration Workflow

A single, linear, ~10-minute script for demonstrating ZeroShield to a supervisor or reviewer in one sitting. Unlike [`docs/HANDOVER.md`](HANDOVER.md) (a reference covering every interface and extension point) or [`docs/TESTING.md`](TESTING.md) (automated verification), this is a **narrated walkthrough** — follow it top to bottom and you will see the whole system work, including the safety gate refusing an unapproved run and a concrete, independently-reproducible result.

Every command below was run for real while writing this document; the output shown is genuine, not illustrative.

Grounded in the SRS's own closeout checklist question — "Can another researcher reproduce the decision?" — and NFR-004 (Reproducibility: "Independent rerun reproduces decisions within documented tolerance").

## Prerequisites

Only the CLI is used for the core walkthrough, which needs no optional extras:

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

(The full `docs/HANDOVER.md` setup — `pip install -e ".[dev]"` — is fine too if you've already got it from an earlier milestone; nothing below needs anything beyond the base install.)

## Step 1 — See the safety gate refuse an unapproved experiment

Both bundled experiments (`ZC-VPN-EXP-001`, `ZC-TELECOM-EXP-001`) ship with `approval_status: "draft"` — nobody has reviewed and approved them yet. Validating under the **default** execution context (`experiment_run`, the real/reviewed path) should correctly refuse them:

```powershell
zeroshield validate-experiment experiments\ZC-VPN-EXP-001.json
```

```
Experiment file: experiments\ZC-VPN-EXP-001.json
Experiment ID: ZC-VPN-EXP-001
Domain: VPN
Schema validation: PASS (includes required research metadata)
Dataset (test_data\vpn\vpn_pre_auth_request_dataset.json): PASS
Safety policy (experiment_run): FAIL
  - SAFE-004: experiment must be approved before execution outside local unit tests (current status: 'draft').

VALIDATION: FAIL
```

This is the safety policy working as intended, not a bug — see [`docs/HANDOVER.md` § Safety controls](HANDOVER.md#5-safety-controls). Confirm it also blocks actual execution, not just validation, and writes nothing:

```powershell
zeroshield run experiments\ZC-VPN-EXP-001.json
```

```
Experiment: ZC-VPN-EXP-001 (domain=VPN)
Safety decision: DENIED (experiment_run)
  - SAFE-004: experiment must be approved before execution outside local unit tests (current status: 'draft').

COMPLETION: FAILED (refused by safety policy before execution)
```

`results\` does not exist yet — nothing was written before the refusal.

## Step 2 — Run both experiments (local_unit_test)

`local_unit_test` is the deliberate, narrower carve-out for exercising a draft experiment locally — every other safety rule (SAFE-001/002/003) still applies, only the approval-status check (SAFE-004) is relaxed. Run both bundled experiments:

```powershell
zeroshield run experiments\ZC-VPN-EXP-001.json --context local_unit_test --baseline-run-id RUN-90001 --mitigation-run-id RUN-90002
zeroshield run experiments\ZC-TELECOM-EXP-001.json --context local_unit_test --baseline-run-id RUN-90003 --mitigation-run-id RUN-90004
```

(Run IDs must match `RUN-<digits>`; explicit IDs are used here only so this document's later steps can refer to them by name — normally you'd omit `--baseline-run-id`/`--mitigation-run-id` and let the CLI generate timestamp-based ones.)

```
Experiment: ZC-VPN-EXP-001 (domain=VPN)
Safety decision: ALLOWED (local_unit_test)
Cases: 22
Baseline status: completed (run_id=RUN-90001)
Mitigation status: completed (run_id=RUN-90002)
Key metrics:
  block_rate: baseline=0.000 mitigation=1.000
  valid_acceptance_rate: baseline=1.000 mitigation=1.000
  block_rate_improvement: 1.000
Evidence output path: results\ZC-VPN-EXP-001

COMPLETION: SUCCESS
```

```
Experiment: ZC-TELECOM-EXP-001 (domain=TELECOM)
Safety decision: ALLOWED (local_unit_test)
Cases: 25
Baseline status: completed (run_id=RUN-90003)
Mitigation status: completed (run_id=RUN-90004)
Key metrics:
  block_rate: baseline=0.000 mitigation=1.000
  valid_acceptance_rate: baseline=1.000 mitigation=1.000
  block_rate_improvement: 1.000
Evidence output path: results\ZC-TELECOM-EXP-001

COMPLETION: SUCCESS
```

Read as: the weak baseline strategy blocked **none** of the malformed/boundary cases (`block_rate: 0.000`); the strict mitigation strategy blocked **all** of them (`block_rate: 1.000`), while still accepting 100% of genuinely valid input in both modes (`valid_acceptance_rate: 1.000` unchanged) — the mitigation improves rejection of bad input without breaking legitimate traffic.

## Step 3 — Verify the evidence is genuine and untampered

Every run's `manifest.json` is hash-verifiable. Check one:

```powershell
zeroshield verify-evidence results\ZC-VPN-EXP-001\RUN-90001
```

```
Manifest: results\ZC-VPN-EXP-001\RUN-90001\manifest.json
Experiment ID: ZC-VPN-EXP-001  Run ID: RUN-90001  Mode: baseline
Artefact files: PASS (4 present)
Manifest integrity (SHA-256): PASS

VERIFICATION: PASS
```

Repeat for `results\ZC-TELECOM-EXP-001\RUN-90003` if you want to show both domains.

## Step 4 — Baseline-vs-mitigation comparison

```powershell
zeroshield compare results\ZC-VPN-EXP-001
```

```
Experiment: ZC-VPN-EXP-001
Baseline run: RUN-90001  Mitigation run: RUN-90002
Total cases: 22
Metric                        Baseline  Mitigation  Difference
processing_success_rate         1.0000      1.0000      0.0000
block_rate                      0.0000      1.0000      1.0000
valid_acceptance_rate           1.0000      1.0000      0.0000
false_positive_rate             0.0000      0.0000      0.0000
false_negative_rate             1.0000      0.0000     -1.0000
parser_reach_rate               1.0000      0.0000     -1.0000
mean_latency_ms                 0.0026      0.0053      0.0027
log_completeness_rate           0.0000      1.0000      1.0000

Block-rate improvement: 1.0000
Latency overhead (ms): 0.0027

Limitations:
  - Results reflect a synthetic, abstracted model of the failure pattern and do not prove mitigation effectiveness for the original vendor product.
  - Metrics are computed only over the cases included in this dataset version and are not a general claim about real-world attack traffic distributions.
```

Note the printed limitations: this is a deliberate, required part of the output (SRS FR-009 "report includes ... limitations"), not something to skip past in a demo — it's the honest boundary of what a synthetic experiment proves.

## Step 5 — Reproducibility check (NFR-004)

Re-run the **same** VPN experiment independently, with fresh run IDs, into a separate location — simulating a different researcher reproducing your result from scratch:

```powershell
zeroshield run experiments\ZC-VPN-EXP-001.json --context local_unit_test --baseline-run-id RUN-90011 --mitigation-run-id RUN-90012 --results-dir results-reproduction-check
zeroshield compare results-reproduction-check\ZC-VPN-EXP-001
```

```
Metric                        Baseline  Mitigation  Difference
processing_success_rate         1.0000      1.0000      0.0000
block_rate                      0.0000      1.0000      1.0000
valid_acceptance_rate           1.0000      1.0000      0.0000
false_positive_rate             0.0000      0.0000      0.0000
false_negative_rate             1.0000      0.0000     -1.0000
parser_reach_rate               1.0000      0.0000     -1.0000
mean_latency_ms                 0.0025      0.0051      0.0026
log_completeness_rate           0.0000      1.0000      1.0000

Block-rate improvement: 1.0000
Latency overhead (ms): 0.0026
```

Compare this against Step 4's table: every rate-based metric (`block_rate`, `valid_acceptance_rate`, `false_positive_rate`, `false_negative_rate`, `parser_reach_rate`, `log_completeness_rate`, `block_rate_improvement`) is **identical**. Only `mean_latency_ms`/`latency_overhead_ms` differ slightly — timing noise from the host machine, not a difference in the decision — which is exactly NFR-004's "reproduces decisions within documented tolerance": the *decision* (accept/block per case, and the resulting rates) is deterministic; wall-clock timing is the only thing that isn't.

Clean up the reproduction-check directory afterward if you don't want it kept: `Remove-Item -Recurse results-reproduction-check`.

## Step 6 (optional) — Interactive views and Overleaf export

The CLI has no export command — Overleaf export is only exposed via the dashboard. If there's time:

- **Dashboard**: follow [README § Running the ZeroShield Dashboard](../README.md#running-the-zeroshield-dashboard), select `ZC-VPN-EXP-001` in the sidebar, and open the **Overleaf Export** tab to generate a factual summary file from the run you just did.
- **API**: follow [README § Running the ZeroShield API](../README.md#running-the-zeroshield-api) and open Swagger (`http://localhost:8000/docs`) to show the same data available programmatically — `GET /experiments/{id}/results` and `GET /experiments/{id}/evidence` will reflect the exact same evidence just generated by the CLI, since every interface reads the same `results/` directory (see [`docs/ARCHITECTURE.md` § Component view](ARCHITECTURE.md#3-component-view-how-a-call-reaches-the-engine)).

Both are genuinely optional — Steps 1–5 alone are a complete, self-contained demonstration.

## What this demonstrated

Mapped back to the SRS's own closeout checklist and Success Definition:

| Checklist question | Shown by |
|---|---|
| "Did the run refuse prohibited behaviour?" | Step 1 — SAFE-004 refusal, before and during execution. |
| "Were baseline and mitigation compared fairly?" | Step 2/4 — same dataset, same runner, both modes, printed side by side. |
| "Can another researcher reproduce the decision?" | Step 5 — independent re-run, identical decision-level metrics. |
| "Evidence manifest verifies successfully" | Step 3. |

**Not** demonstrated here, honestly: neither bundled experiment is actually **approved** — this codebase has no automated approval workflow (`approval_status` is a field a human reviewer edits after review, per SRS §3's "Reviewer" role; see `zeroshield.policies.rules.check_safe_004_approval_status`). This walkthrough used `local_unit_test` specifically because that step — supervisor sign-off — is a human decision outside this software, not something ZeroShield itself performs.
