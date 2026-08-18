# ZeroShield V2 Plan: Roadmap, Status, and Documentation Map

A single, concise index of where every V2 documentation topic actually
lives. No separate `V2_*`-prefixed documents exist in this repository, and
none should be created going forward - each topic below has exactly one
authoritative home. If you're looking for V2 information and it isn't
listed here, it doesn't have a dedicated document yet; check
[`docs/HANDOVER.md`](HANDOVER.md) first, since it's the general-purpose
entry point.

## Phase status

| Phase | Status | Primary doc |
|---|---|---|
| 1 - Platform Foundation (Postgres run-lifecycle) | Complete | [`ARCHITECTURE.md` §6a](ARCHITECTURE.md#6a-v2-platform-foundation-postgresql-run-lifecycle-system-of-record) |
| 2 - Threat Intelligence & Prioritisation | Complete | [`ARCHITECTURE.md` §6b](ARCHITECTURE.md#6b-v2-phase-2-threat-intelligence--prioritisation) |
| 3 - Advanced Validation Platform (Studio, Domain Packs) | Complete | [`ARCHITECTURE.md` §6c](ARCHITECTURE.md#6c-v2-phase-3-advanced-validation-platform) |
| 4 - Professional Web Application | Complete | [`apps/web/README.md`](../apps/web/README.md) |
| 5 - AI & Continuous Assurance | Complete | [`ARCHITECTURE.md` §6d](ARCHITECTURE.md#6d-v2-phase-5-ai--continuous-assurance) |
| 6 - Hardening & Final Local V2 Release | Complete, including a final release verification/fix pass | [`ARCHITECTURE.md` §6e](ARCHITECTURE.md#6e-v2-phase-6-hardening--final-local-v2-release) |

## Topic → document map

| Topic | Document | Covers |
|---|---|---|
| Architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md) | Seven-layer logical architecture, design patterns, component/deployment views, per-phase design sections (§6a-§6e), sequence diagrams. |
| Security | [`SECURITY.md`](SECURITY.md) | Authentication, RBAC, self-approval blocking, the audit trail, the security test suite, and what was deliberately left alone (CLI, legacy dashboard). |
| Operations / deployment | [`DEPLOYMENT.md`](DEPLOYMENT.md) | CI, the one-command Docker Compose release, first-time setup, port table, and this document's final release verification report. |
| Testing | [`TESTING.md`](TESTING.md) | How to run and interpret every test tier: unit, integration, security, observability, E2E (Playwright), and the live V2 release acceptance suite. |
| Handover | [`HANDOVER.md`](HANDOVER.md) | What ZeroShield is, setup, execution, extension points, and safety controls - the general entry point for a new reader. |
| Observability | [`OBSERVABILITY.md`](OBSERVABILITY.md) | Prometheus metrics, structured JSON logging, and distributed tracing - including exactly where tracing starts (FastAPI, not the browser) and what request_id vs. trace_id each cover. |
| Future opportunities | [`FUTURE_OPPORTUNITIES.md`](FUTURE_OPPORTUNITIES.md) | Documentation-only notes on cloud/Kubernetes/SaaS/SSO directions - explicitly not implemented, not scheduled. |
| Demonstration | [`DEMONSTRATION.md`](DEMONSTRATION.md) | A guided walkthrough script, both the original CLI-only path and the V2 Phase 6 web/RBAC/audit path. |
| CLI reference | [`CLI_REFERENCE.md`](CLI_REFERENCE.md) | Every `zeroshield` command, including `create-admin`. |
| Configuration reference | [`CONFIGURATION.md`](CONFIGURATION.md) | Every environment variable and dependency extra. |
| Traceability (SRS compliance) | [`TRACEABILITY.md`](TRACEABILITY.md) | The Milestone 30 requirement-by-requirement review - a historical snapshot, predates V2, deliberately left unmodified rather than rewritten. |

## Final release verification pass (V2 Phase 6 follow-up)

A dedicated audit pass closed the gap between "the code exists and unit
tests pass" and "a completely fresh `docker compose up` actually works,
end to end, for real." It found and fixed real bugs a review of the code
alone would not have caught - a fresh database was never migrated, two
service pairs silently didn't share a filesystem in the containerised
deployment, an evidence-backend mismatch made runs invisible through the
API, and a non-atomic file write raced under genuine concurrent access.
See [`DEPLOYMENT.md`](DEPLOYMENT.md) for the full list of bugs found, fixes
applied, and the actual (not claimed) execution results of the live,
eight-scenario release acceptance suite
(`tests/integration/test_v2_release_acceptance.py`).

## What's explicitly not planned

Cloud deployment, Kubernetes, SaaS/multi-tenancy, and SSO are documented as
directional notes only, in [`FUTURE_OPPORTUNITIES.md`](FUTURE_OPPORTUNITIES.md) -
none of it is implemented, scheduled, or assumed by any code here. V2 Phase
6 is the final implementation phase of this engagement.
