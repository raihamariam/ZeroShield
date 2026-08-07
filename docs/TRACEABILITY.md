# ZeroShield — Final Traceability and SRS Compliance Review (Milestone 30)

This is the SRS's own closeout item: "a requirement-by-requirement audit of which `FR-*`/`NFR-*`/`SAFE-*`/`AC-*` identifier is satisfied where" (see [`docs/ARCHITECTURE.md` §7](ARCHITECTURE.md#7-what-this-document-deliberately-does-not-cover), which deferred exactly this to Milestone 30). It also resolves **D-05** (evidence repository & retention policy), which Milestone 24 was folded into per the project roadmap.

**Method.** Every row below was checked directly against the current `src/zeroshield` code and `tests/` suite as of this review — not copied from `HANDOVER.md`/`ARCHITECTURE.md`/`TESTING.md`'s claims, though those turned out to be accurate almost everywhere they made a claim (one inconsistency found and fixed, see [§8](#8-corrections-made-to-other-docs-as-part-of-this-review)). Where a requirement is not fully met, that's stated plainly, per this project's established practice of documenting gaps rather than implying completeness (`docs/TESTING.md`'s "Known gaps" section is the precedent). The full test suite (`pytest -q --cov=src/zeroshield`) was re-run for this review: **559 passed, 1 skipped** (the opt-in real-broker test), **99% coverage** of `src/zeroshield`; `tests/policy` + `tests/security` alone: **86 passed, 0 failed**.

**Status legend:** ✅ Met · 🟡 Partially met (works, but narrower than the literal requirement text) · ⛔ Not met · ⬜ Not implemented (by design, deferred) · N/A not yet applicable given current project state.

## 1. Headline findings

Two things are not documented as open anywhere else in this repository, and are the most important output of this review:

1. **AC-01 and AC-10 are not met.** Both bundled experiments (`ZC-VPN-EXP-001`, `ZC-TELECOM-EXP-001`) still have `"approval_status": "draft"` — neither has ever been through supervisor review, and no review-decision record exists anywhere in the repo (no `POST /experiments/{id}/reviews`, no decision log file). This isn't a bug: it's downstream of §17's Open Decisions (D-01–D-03, D-06, D-07) never having been closed by an actual Project Lead/Advisor/Learning Facilitator, because this project has been executed solo without a live reviewer. `tests/unit/test_vpn_acceptance_criteria.py` and `test_telecom_acceptance_criteria.py` already say this in their own docstrings, but no top-level doc (README/HANDOVER/ARCHITECTURE) stated it as a standing compliance gap before this review.
2. **D-05 (evidence repository & retention policy)** is resolved in [§7](#7-open-decisions-§17-status) below: the repository half is answered by what was actually built; the retention half is a **proposed** policy, not an approved one, for the same reason as finding 1 — there is no Project Lead available to approve it within this solo execution.

Everything else below is either fully met, or a narrower-than-literal partial match, or an explicitly deferred/optional item consistent with the SRS's own §2.2 scope list.

## 2. Functional Requirements (§5)

| ID | Pri | Status | Evidence | Note |
|---|---|---|---|---|
| FR-001 | M | ✅ | `models/experiment_definition.py` (`ExperimentDefinition`, `extra="forbid"`, 5 model validators); `tests/unit/models/test_experiment_definition.py` | |
| FR-002 | M | 🟡 | `models/_shared.py` (`ExperimentId` type); IDs are frozen per-model | `discover_experiments`/`find_experiment` (`experiments/discovery.py`) never check for a duplicate `experiment_id` across two files — the acceptance text ("duplicate IDs cannot be stored") is not enforced at the store level, only true today because exactly two experiment files exist with distinct IDs. No test covers this scenario. |
| FR-003 | M | ✅ | `related_cves`/`source_references` required fields on `ExperimentDefinition`; SAFE-policy does not gate on this directly but schema validation does | |
| FR-004 | M | ✅ | `models/enums.py` (`RootCauseCategory`, `Domain`, `InputClassification`, etc.) | |
| FR-005 | M | ✅ | `datasets/loader.py`; `TestCase` model carries `category` (valid/malformed/boundary) + `expected_outcome` + provenance | |
| FR-006 | M | ✅ | `orchestration/experiment_orchestrator.py`: one `load_test_set` call feeds both baseline and mitigation runs — mismatched datasets are structurally impossible, not runtime-rejected | Satisfied by construction rather than an explicit mismatch-check. |
| FR-007 | M | ✅ | `models/case_result.py` (`Decision`, `parser_reached`, `errored`, logging outcome — one record per case) | |
| FR-008 | M | ✅ | `metrics/calculator.py` (block rate, valid acceptance, FP/FN, parser reach, latency, log completeness) | |
| FR-009 | M | ✅ | `metrics/comparator.py` + `models/comparison_report.py`; limitations text always included (`docs/DEMONSTRATION.md` Step 4 shows real output) | |
| FR-010 | M | ✅ | `repositories/evidence_builder.py`; all §15.2 fields present — see [§5](#5-evidence-manifest-fields-§152) | |
| FR-011 | M | ✅ | `runners/experiment_runner.py:ExperimentRunner.run()` evaluates `SafetyPolicy` before any case executes; `PolicyRefusalError` pre-execution | |
| FR-012 | M | ✅ | `models/enums.py:ApprovalStatus` (draft/pending_review/approved/revision_required/rejected/closed); `SAFE-004` enforces approved-only | |
| FR-013 | S | 🟡 | `api/routes/experiments.py`, `api/routes/jobs.py`, `api/routes/evidence.py` | Implemented surface: `GET /experiments`, `GET /experiments/{id}`, `POST /experiments/{id}/validate`, `POST /experiments/{id}/runs`, `GET /jobs/{job_id}`, `GET /experiments/{id}/results`, `GET /experiments/{id}/evidence`, `GET /health`, `GET /metrics`. **Missing vs SRS §8.2**: `POST /experiments` (create), `POST /experiments/{id}/reviews` (record decision), and `GET /runs/{run_id}` was redesigned as job-based (`GET /jobs/{job_id}`) since execution is queued/async, not synchronous-by-run-id. FR-013's own acceptance text ("API validates schema and returns stable identifiers/status") is still met. |
| FR-014 | S | ✅ | `api/routes/experiments.py:submit_run` → RabbitMQ → `worker/main.py` + `worker/processor.py` | |
| FR-015 | S | ✅ | `repositories/minio_evidence_repository.py`; immutable prefixes; `tests/security/test_evidence_immutability.py` covers both backends | |
| FR-016 | S | ✅ | `observability/metrics.py`; scraped per `monitoring/prometheus.yml` | |
| FR-017 | C | 🟡 | `monitoring/grafana/provisioning/dashboards/zeroshield.json` (4 panels: API request rate, worker job outcomes, worker job duration, experiment runs submitted) | All 4 panels are operational/service-health; zero scientific (block-rate/metric-comparison) panels exist, so there's nothing for the dashboard to visually *distinguish* between the two categories the requirement names — the intent (keep scientific evidence out of the ops dashboard) is met, but the literal "distinguishes X from Y" acceptance isn't, since only one category is present. |
| FR-018 | C | ⬜ | — | Not implemented. Consistent with SRS §2.2 "Automated Excel ingestion" deferred list. |
| FR-019 | C | ⬜ | — | Not implemented. Consistent with SRS §2.2 "prioritisation engine" deferred list. |
| FR-020 | C | ⬜ | — | Not implemented. Consistent with SRS §2.2 "Recovery Readiness Index" deferred list. |

## 3. Non-Functional Requirements (§9)

| ID | Attribute | Status | Evidence / measure |
|---|---|---|---|
| NFR-001 | Security | ✅ | No strategy (`strategies/vpn/*`, `strategies/telecom/*`) performs any network I/O — pure functions over `dict` — so there is no code path that could reach an external destination today, by absence rather than by an enforced network policy (see SAFE-005 gap, §4). |
| NFR-002 | Safety | ✅ | `pytest -q tests/policy tests/security` → **86 passed, 0 failed** — 100% pass rate as required. |
| NFR-003 | Traceability | N/A | Requirement is "100% of *closed* experiments have complete lineage" — no experiment has ever reached `closed` status (both remain `draft`), so this is vacuously true today, not demonstrated. Re-check once an experiment is actually closed out. |
| NFR-004 | Reproducibility | ✅ | `tests/unit/test_reproducibility.py` — two independent `ExperimentRunner` invocations produce identical dataset hashes and identical per-case decisions, both domains. Also demonstrated live in `docs/DEMONSTRATION.md` Step 5. |
| NFR-005 | Reliability | ✅ | `runners/experiment_runner.py:_execute_case` wraps `strategy.process()`; any exception becomes a `BLOCKED`+`errored=True` result, not an aborted run. |
| NFR-006 | Performance | 🟡 | `metrics/comparator.py` always reports `latency_overhead_ms` (mean). No p50/p95 percentile breakdown exists — the SRS's specific "report p50/p95" measure is not met, only mean latency is. |
| NFR-007 | Maintainability | ✅ | Strategy + Registry pattern (`strategies/registry.py`); `ExperimentRunner` only calls `strategy.process()` through the ABC — a new strategy needs zero runner changes. |
| NFR-008 | Testability | ✅ | `pytest -q --cov=src/zeroshield --cov-report=term-missing` → 99% overall; `policies/rules.py` and `policies/safety_policy.py` at **100%** (target was 100% for safety-policy paths, ≥85% elsewhere — both exceeded). |
| NFR-009 | Usability | ✅ | `docs/HANDOVER.md` §2 is written and cross-checked to be sufficient for a from-scratch setup; not independently re-verified on a clean machine during this review pass. |
| NFR-010 | Portability | 🟡 | Confirmed working on Windows (this review ran on win32). No CI directory exists (no `.github/workflows`) and no recorded second-OS manual smoke test — the "at least two environments" measure is not evidenced. |
| NFR-011 | Observability | ✅ | `models/case_result.py`: `run_id`/`case_id` are non-optional fields — structurally impossible for a result to lack them. |
| NFR-012 | Scalability | ✅ | `tests/unit/strategies/test_strategy_contract.py` (contract tests) + `tests/integration/test_api_worker_real_broker.py` (real-broker contract test, opt-in, passes when run). |
| NFR-013 | Accessibility | 🟡 | Docs use headings/tables/Mermaid with text content throughout, but no doc records an explicit accessibility review against this requirement ID. |
| NFR-014 | Sustainability | 🟡 | No `docs/DECISIONS.md`-style artefact records a benefit/cost check before each optional service (RabbitMQ/MinIO/Prometheus/Grafana) was enabled — the practice described in §13.4 isn't captured as a standing document, though each Milestone 20–23 commit message states its own rationale. |

## 4. Safety / Policy-as-Code Rules (§10.1)

| Rule | Status | Evidence |
|---|---|---|
| SAFE-001 | ✅ | `policies/rules.py:check_safe_001_external_targeting`; `tests/policy/test_rules.py` |
| SAFE-002 | ✅ | `policies/rules.py:check_safe_002_input_classification`; tested |
| SAFE-003 | ✅ | `policies/rules.py:check_safe_003_weaponised_payloads`; tested |
| SAFE-004 | ✅ | `policies/rules.py:check_safe_004_approval_status`; tested; demonstrated live in `docs/DEMONSTRATION.md` Step 1 |
| SAFE-005 | ⬜ | Not implemented. Confirmed by reading `Dockerfile`/`docker-compose.yml` directly: no network policy, no `cap_drop`, no non-root `USER`, no read-only filesystem, no resource limits on any service (`api`, `worker`, `dashboard` all run as root today). `docs/TESTING.md`'s stated reason ("no sandbox container execution exists yet to test against") is accurate — this is a container-hardening gap beyond just a missing test, since the containers that *do* exist aren't hardened either, even though no untrusted code currently runs in them. |
| SAFE-006 | ✅ | `tests/security/test_static_analysis_guards.py` — real regex-based secret scan over checked-in `experiments/`/`test_data/`, passing. **`docs/HANDOVER.md` previously stated SAFE-005–008 were all "not yet implemented," which was stale/inconsistent with `docs/TESTING.md`'s own security-suite table — corrected as part of this review, see §8.** |
| SAFE-007 | ⬜ | Not implemented. No code or test anywhere checks logs for personal/confidential content. Unlike SAFE-005/008, this gap was not previously acknowledged in `docs/TESTING.md`'s "Known gaps" section either — it is newly documented here. |
| SAFE-008 | 🟡 | Rejection itself works (`PolicyRefusalError`) and the **async** path records it (`worker/processor.py` saves `JobStatus.DENIED` + reasons to the job store). The **synchronous CLI** path (`cli/commands.py:run_experiment`) only prints the refusal to stdout and persists nothing — there is no unified, persistent safety-violation log across both execution paths. Not previously documented as a gap. |

## 5. Acceptance Criteria (§11.3)

| AC | Status | Evidence |
|---|---|---|
| AC-01 | ⛔ | `experiments/ZC-VPN-EXP-001.json:81` and `ZC-TELECOM-EXP-001.json:94` both have `"approval_status": "draft"`. Neither experiment has ever been approved. |
| AC-02 | 🟡 | CVE linkage, GitHub task references and source URLs are present and schema-checked; GitHub/Overleaf cross-linking itself is out of scope for automated verification (acknowledged in the test files themselves). |
| AC-03 | ✅ | `tests/unit/test_vpn_acceptance_criteria.py`, `test_telecom_acceptance_criteria.py` |
| AC-04 | ✅ | same, plus `docs/DEMONSTRATION.md` Step 2's live `block_rate: mitigation=1.000` output |
| AC-05 | ✅ | one dataset load feeds both modes (FR-006) |
| AC-06 | ✅ | every rejection produces a structured `CaseResult`/log entry — `test_vpn_acceptance_criteria.py` |
| AC-07 | ✅ | `metrics/comparator.py` output includes all named dimensions — `docs/DEMONSTRATION.md` Step 4 table |
| AC-08 | ✅ | `tests/security/test_evidence_immutability.py`; `verify-evidence` CLI command; `docs/DEMONSTRATION.md` Step 3 |
| AC-09 | ✅ | `tests/security/test_static_analysis_guards.py` (no dangerous execution primitives); synthetic-only inputs enforced by SAFE-002/003 |
| AC-10 | ⛔ | No review-decision record exists anywhere in the repository (no `POST /experiments/{id}/reviews` implemented, no decision-log artefact). |

## 6. RTM Objectives Sanity Check (§16)

The SRS's own objective→requirement groupings still hold structurally — every FR/NFR/AC ID cited under each objective exists and still means what it meant. One overstatement: **OBJ-6 ("Extensibility", FR-013–FR-020)** is only about 5/8 (62%) delivered — FR-018/019/020 are wholly unimplemented (§2) — so labelling the whole group "post-Phase-1 roadmap" understates that three of the eight items were never started, not merely deferred with partial progress like FR-017.

## 7. Open Decisions (§17) Status

| ID | Question | Status |
|---|---|---|
| D-01 | Exact VPN CVE pattern | Still open — owner is Project Lead, who has not been available to close it within this solo execution; the pre-authentication-request-validation candidate in §6.1 was used as a working assumption, never formally confirmed. |
| D-02 | Exact telecom pattern | Same as D-01, for the §6.2 SIP-like candidate. |
| D-03 | Real vulnerable images/PoCs authorised? | Still open; the project has proceeded on the conservative assumption of "no" (synthetic-only throughout), consistent with C-04. |
| D-04 | Acceptable performance overhead | Still open; no experiment-specific overhead threshold has ever been set or enforced in code — see NFR-006 (🟡) above. |
| **D-05** | **Evidence repository & retention policy** | **Resolved in this review — see below.** |
| D-06 | Is FastAPI/RabbitMQ/MinIO/Grafana delivery required or optional? | Answered in practice, not formally: all four were built (Milestones 19–23) despite being nominally optional per C-05/§2.2. Formal Project-Lead sign-off on "required" vs "optional" was never recorded. |
| D-07 | Assessment 2 word limit (1,200 vs 1,500) | Out of this codebase's scope entirely — owner is the Learning Facilitator, not something a compliance review of the software can resolve. |

### D-05 resolution

**The repository half of D-05 is answered by what was actually built, not by a supervisor decision.** `EvidenceRepository` (`repositories/evidence_repository.py`) is an ABC with two concrete implementations built behind it (Repository pattern, SRS §4.2): `LocalEvidenceRepository` (default, filesystem under `results/`) and `MinioEvidenceRepository` (optional, S3-compatible, Milestone 22). Both are already required to satisfy the same contract and the same immutability guarantee (`EvidenceAlreadyExistsError` — verified present and tested in both), so "which repository" was never a hard fork in the design: it's a deployment-time choice of which concrete class gets constructed, not a decision that blocks anything.

**The retention half is genuinely still open**, and this review does not close it — it proposes it, consistent with how this project has always handled decisions without a live reviewer (the SRS itself is still "Status: Proposed; subject to supervisor validation," per its own cover page). Verified before writing this: there is **zero** retention/expiry/deletion logic anywhere in `src/zeroshield` (grepped `retention|expire|expiry|ttl|delete`, no matches), and no data-classification field exists on `ExperimentDefinition` or `EvidenceManifest` — §7.3's "Internal/Research" default classification is a documentation-only concept today, not a code-enforced one.

**Proposed retention policy (pending Project Lead approval — not yet binding):**

1. **Classification.** All Phase-1 evidence defaults to *Internal / Research*, per §7.3, because Phase-1 scope is synthetic-only by construction (SAFE-002, C-04) — no vendor-restricted, confidential, or exploit-capable content should ever exist in `results/` under the current experiment set.
2. **Duration.** Keep all raw run evidence (manifest + artefacts) for the life of the project/placement, plus a minimum of 12 months past whatever closeout sign-off the Project Lead eventually records (§18), to support later audit questions (§15.3) or re-review. No scheduled automatic deletion — evidence is already append-only/immutable by construction (`EvidenceAlreadyExistsError`), so the default posture is "retain," not "expire on a timer."
3. **Deletion authority.** Only the Project Lead may authorise deletion or pruning, recorded as a decision-log entry (§13.4). This is trivially enforced today by *absence of capability*: no code path in this repository deletes evidence at all (verified — no delete/expire logic exists), so nothing can be deleted accidentally or by policy violation; it can only be deleted by someone with direct filesystem/bucket access outside the application.
4. **Backend choice does not affect the policy.** Local vs. MinIO is a deployment-time choice (single machine/offline vs. Docker-based deployment); both produce byte-identical manifest schemas, so switching backends is a copy operation, not a migration requiring a different retention rule.
5. **Not yet operationalised in code**, and deliberately out of scope for this review milestone (M30 is an audit, not a feature milestone): automatic TTL/lifecycle enforcement, and a machine-readable classification field on `EvidenceManifest`/`ExperimentDefinition`. Recorded here as backlog per §18 ("Deferred architecture and future research are moved to a prioritised backlog").

**D-05 status: partially resolved.** Repository choice — closed by delivery. Retention policy — proposed above, pending an actual Project Lead approval this project does not currently have access to grant.

## 8. Corrections made to other docs as part of this review

- **`docs/HANDOVER.md` § Safety controls** previously stated "SAFE-005 through SAFE-008 are specified in the SRS but not yet implemented," which contradicted `docs/TESTING.md`'s own security-suite table (SAFE-006 is covered by `test_static_analysis_guards.py`, and has been since Milestone 26). Corrected to state SAFE-006 is implemented and to individually describe SAFE-005/007/008 (all still gaps, but SAFE-008 is partial, not absent — see §4 above).

## 9. Data Integrity Rules (§7.2)

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | IDs immutable after creation | 🟡 | `experiment_id`/`run_id` fields are frozen at the Pydantic-model level (in-memory immutability); no store-level uniqueness check across files exists — see FR-002 above. |
| 2 | Raw results append-only | ✅ | `EvidenceAlreadyExistsError` in both `LocalEvidenceRepository` and `MinioEvidenceRepository`; tested. |
| 3 | Comparison requires identical version/hash | ✅ | Satisfied by construction — one dataset load feeds both modes (FR-006). |
| 4 | Source URLs/dates retained | ✅ | `models/cve_reference.py`: `source_urls: list[HttpUrl]`, `retrieved_date: date`, both required. |
| 5 | No unapproved sensitive content | 🟡 | Enforced only for checked-in fixture data (SAFE-006's static scan); nothing scans `results/` after a live run completes. |
| 6 | SHA-256 (or equivalent) manifest hashes | ✅ | `repositories/evidence_builder.py` (`hashlib.sha256` over canonicalised JSON) for both `test_set_sha256` and `manifest_sha256`. |

## 10. Evidence Manifest Fields (§15.2)

All 17 fields listed in the SRS example are present on `models/evidence_manifest.py:EvidenceManifest`: `manifest_version`, `experiment_id`, `experiment_version`, `run_id`, `mode`, `test_set_id`, `test_set_sha256`, `git_commit`, `container_image_digest`, `started_at`, `completed_at`, `strategy_id`, `metrics`, `artefact_paths`, `safety_decision`, `review_status`, `manifest_sha256`. No field is missing.

One field is a placeholder in practice: `container_image_digest: str | None` is hardcoded to `None` in `evidence_builder.py` — never populated even when a run executes inside the Docker image built by Milestone 20. Populating it (e.g. from an environment variable set at image build time) is future work, not a schema gap.

## 11. Interface Requirements (§8)

- **§8.1 CLI** — ✅ all four mandatory commands exist with matching semantics: `validate-experiment`, `run`, `compare`, `verify-evidence` (`cli/commands.py`; full reference in `docs/CLI_REFERENCE.md`).
- **§8.2 API** — 🟡 see FR-013 above: 7 of 9 listed endpoints exist as specified or reasonably adapted for the async execution model actually built; `POST /experiments` (create via API) and `POST /experiments/{id}/reviews` (record a supervisor decision via API) are genuinely absent. Adding the latter would also close part of AC-10's gap.

## 12. Overall compliance verdict

Phase 1's **engineering baseline is essentially complete**: every Must-priority functional requirement (FR-001–012), the full safety-policy Must set relevant to Phase 1 (SAFE-001–004), and 7 of 10 acceptance criteria are met with direct, automated test evidence, not just documentation claims. The optional infrastructure list (§2.2) was substantially over-delivered (all of Docker/RabbitMQ/MinIO/Prometheus/Grafana built, despite being explicitly optional per C-05).

What remains open is **not an engineering gap** — it's the set of decisions that only exist because a live Project Lead/Advisor/Learning Facilitator was never available to make them (§17), which cascades into AC-01/AC-10 being unmet by definition (nothing can be "approved" without an approver) and D-01–D-04/D-06/D-07 staying open. This review's job was to make that boundary explicit rather than leave it implicit, per §18's own closeout requirement: "The final ... conclusion distinguishes demonstrated outcomes from future claims." A handful of smaller, genuinely-actionable code/doc gaps were also found and are listed above (FR-002 dedup, SAFE-007, SAFE-008's CLI-path logging, `container_image_digest` placeholder, NFR-006's missing percentile breakdown) — none block Phase 1's success definition (§1.5), which only requires the two experiments to run in both modes with comparable metrics and complete evidence manifests, which they do.
