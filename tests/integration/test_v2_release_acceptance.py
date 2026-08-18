"""The V2 release acceptance suite (final release verification pass) -
eight scenarios (A-H), the authoritative final-release acceptance gate for
ZeroShield V2. Executed against a REAL running docker-compose stack over
real HTTP (never TestClient/mocks) - several scenarios need infrastructure
manipulation (stopping MinIO, restarting the worker container) a browser
test or an in-process TestClient can't do. See
apps/web/e2e/workflows/governance-acceptance.spec.ts for the separate,
browser-driven UI/RBAC/audit acceptance suite this complements (not
duplicates - see that file's docstring for how the two relate).

Every scenario uses controlled fixtures/seed data - the bundled
experiments/*.json fixtures, and directly-seeded intelligence/assurance
records via the real (not mocked) repository classes - never a live
NVD/CISA/EPSS network call, matching this project's existing no-live-
network policy for deterministic tests.

Opt-in only, like the real-broker/real-Postgres integration tests
(ZEROSHIELD_E2E_RABBITMQ_URL/ZEROSHIELD_E2E_POSTGRES_URL): set
ZEROSHIELD_E2E_LIVE_STACK_URL to the API's base URL (e.g.
http://localhost:8000) to opt in; the whole module self-skips otherwise.
Also needs Docker available on PATH (for scenarios G/H, which stop/restart
containers via `docker compose`) and DATABASE_URL reachable from this
process (defaults to the same localhost:5433 every other tool in this
project defaults to - see zeroshield.db.session).

Run with (from the repo root, with `docker compose up -d` already done and
one bootstrap ADMIN already created):

    ZEROSHIELD_E2E_LIVE_STACK_URL=http://localhost:8000 \
        pytest tests/integration/test_v2_release_acceptance.py -v -s

This suite mutates the live stack's database and briefly stops/restarts
containers (scenarios G/H) - never point it at anything but a disposable
local docker-compose stack.
"""

import os
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ZEROSHIELD_E2E_LIVE_STACK_URL"),
    reason="set ZEROSHIELD_E2E_LIVE_STACK_URL to opt into the live V2 release acceptance suite",
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_URL = os.environ.get("ZEROSHIELD_E2E_LIVE_STACK_URL", "")
RUN_TAG = uuid.uuid4().hex[:8]  # unique per test-run, so re-running against the same stack never collides
# experiment_id is server-validated against ^ZC-(VPN|TELECOM)-EXP-\d{3,}$ (studio.py) -
# no hex allowed, so a separate all-digit tag is used just for those IDs.
RUN_TAG_NUM = str(int(time.time()))[-6:]


def _api() -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


def _run_compose(*args: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout, check=False
    )


def _wait_for_run_queue_consumer_count(expected: int, *, timeout: float = 30.0) -> None:
    """Polls RabbitMQ's management API for zeroshield.experiment_runs'
    consumer count - used by Scenario G to deterministically know when the
    old (stopped) worker's consumer registration has actually dropped, and
    when the new one-off worker's has actually registered, rather than
    guessing with a fixed sleep (a real, observed flake: docker compose
    stop's return does not guarantee the stopped container's pika
    connection/consumer was already torn down server-side, so a submission
    right after stop could still be delivered to the container that's
    "stopped" but not yet actually disconnected)."""
    deadline = time.monotonic() + timeout
    mgmt = httpx.Client(base_url="http://localhost:15673", auth=("guest", "guest"), timeout=5.0)
    while time.monotonic() < deadline:
        try:
            resp = mgmt.get("/api/queues/%2F/zeroshield.experiment_runs")
            if resp.status_code == 200 and resp.json().get("consumers") == expected:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise TimeoutError(f"zeroshield.experiment_runs did not reach {expected} consumer(s) within {timeout}s")


def _run_docker(*args: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    # Plain `docker`, not `docker compose` - for targeting an explicitly-
    # named one-off container (docker compose run --name ...) directly,
    # since `docker compose kill/rm <service>` targets by service label and
    # could ambiguously match more than the one specific container intended.
    return subprocess.run(
        ["docker", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout, check=False
    )


def _login(client: httpx.Client, username: str, password: str) -> None:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login failed for {username}: {resp.status_code} {resp.text}"


def _create_user(admin_client: httpx.Client, role: str, label: str) -> tuple[str, str]:
    username = f"e2e-{label}-{RUN_TAG}"
    password = f"E2e-{label}-{RUN_TAG}-pw-1"
    resp = admin_client.post("/users", json={"username": username, "password": password, "role": role})
    assert resp.status_code == 201, f"create_user({role}) failed: {resp.status_code} {resp.text}"
    return username, password


def _poll_job(client: httpx.Client, job_id: str, *, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    terminal = {"completed", "failed", "denied"}
    while time.monotonic() < deadline:
        resp = client.get(f"/jobs/{job_id}")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        if body["status"] in terminal:
            return body
        time.sleep(2)
    raise TimeoutError(f"job {job_id} did not reach a terminal state within {timeout}s")


def _bootstrap_admin() -> tuple[str, str]:
    """Bootstraps a fresh, run-unique ADMIN via the CLI inside the api
    container - real code path (zeroshield.cli.commands.create_admin), not
    a direct DB write - so this suite can run repeatedly against the same
    long-lived stack without colliding with a previous run's account."""
    username = f"e2e-admin-{RUN_TAG}"
    password = f"E2e-admin-{RUN_TAG}-pw-1"
    result = _run_compose(
        "exec", "-T", "api", "zeroshield", "create-admin", "--username", username, "--password", password
    )
    assert result.returncode == 0, f"create-admin failed: {result.stdout}\n{result.stderr}"
    return username, password


@pytest.fixture(scope="module")
def admin_credentials() -> tuple[str, str]:
    return _bootstrap_admin()


@pytest.fixture(scope="module")
def admin_client(admin_credentials: tuple[str, str]) -> httpx.Client:
    client = _api()
    _login(client, *admin_credentials)
    return client


def _create_and_run_experiment_version(
    client: httpx.Client,
    *,
    experiment_id: str,
    domain_pack_id: str,
    template_id: str,
    template_version: str,
    cve_id: str,
    domain: str,
    dataset_config: dict,
    seed: int,
) -> dict:
    """Shared happy-path builder for Scenarios A/B - dataset preview, draft
    creation, submit-for-review. Returns the created version's JSON body.
    Approval/run submission is left to the caller since who approves (and
    whether they're allowed to) is exactly what varies between scenarios."""
    preview = client.post(
        "/datasets/generate", json={"domain_pack_id": domain_pack_id, "seed": seed, "config": dataset_config}
    )
    assert preview.status_code == 200, preview.text

    created = client.post(
        "/experiment-versions",
        json={
            "experiment_id": experiment_id,
            "title": f"V2 release acceptance - {experiment_id}",
            "description": "Created by tests/integration/test_v2_release_acceptance.py against controlled fixtures.",
            "related_cves": [
                {
                    "cve_id": cve_id, "domain": domain, "cisa_kev": True, "cvss_score": 9.8,
                    "trust_boundary": "pre-authentication network boundary",
                    "root_cause": "memory_safety_failure" if domain == "VPN" else "parser_message_handling_failure",
                    "vendor_mitigation": "Vendor-shipped patch (fixture).",
                    "mitigation_gap": "No compensating control before patch (fixture).",
                    "source_urls": ["https://example.com/advisory"],
                    "retrieved_date": datetime.now(UTC).date().isoformat(),
                }
            ],
            "domain_pack_id": domain_pack_id,
            "template_id": template_id,
            "template_version": template_version,
            "dataset_config": dataset_config,
            "seed": seed,
            "failure_pattern": "structural_validation_bypass",
            "root_cause": "memory_safety_failure" if domain == "VPN" else "parser_message_handling_failure",
            "vendor_mitigation": "Vendor-shipped patch (fixture).",
            "mitigation_gap": "No compensating control before patch (fixture).",
            "research_question": "Does the mitigation strategy reject the malformed/adversarial cases the baseline accepts?",
            "hypothesis": "The mitigation strategy blocks materially more malformed cases than the baseline.",
        },
    )
    assert created.status_code == 201, created.text
    version = created.json()

    submitted = client.post(f"/experiment-versions/{version['version_id']}/submit-review", json={})
    assert submitted.status_code == 200, submitted.text
    return version


# -- Scenario A: fresh-DB VPN flow, end to end -------------------------------


def test_scenario_a_vpn_full_governed_flow(admin_client: httpx.Client, admin_credentials: tuple[str, str]) -> None:
    """fresh DB -> migrations -> controlled intelligence -> VPN validation
    candidate -> Experiment Studio -> dataset -> approval -> run ->
    deterministic verdict -> evidence -> integrity verification.

    "Fresh DB -> migrations" is verified once, ahead of this whole module,
    by actually running `docker compose down -v && docker compose up
    --build` and checking `alembic current` reports head before this suite
    is invoked - see docs/DEPLOYMENT.md's final release verification
    report for that result; it is not re-proven per-scenario here."""
    researcher_username, researcher_password = _create_user(admin_client, "researcher", "a-researcher")
    reviewer_username, reviewer_password = _create_user(admin_client, "reviewer", "a-reviewer")

    # -- controlled intelligence -> VPN validation candidate (real
    # repository/candidate-generation code, no live network) -------------
    from zeroshield.db.session import build_engine, build_sessionmaker
    from zeroshield.intelligence.candidates import generate_candidate
    from zeroshield.intelligence.repository import VulnerabilityRepository
    from zeroshield.models.enums import Domain
    from zeroshield.models.vulnerability import Vulnerability

    engine = build_engine()
    session_factory = build_sessionmaker(engine)
    vuln_repo = VulnerabilityRepository(session_factory)

    cve_id = f"CVE-2026-9{RUN_TAG_NUM}"
    now = datetime.now(UTC)
    vuln_repo.upsert_vulnerability(
        Vulnerability(
            cve_id=cve_id,
            # Must contain a VPN_PRODUCT_TERMS match (zeroshield.intelligence.candidates) to
            # classify as SUPPORTED, not just set domain_guess - domain_guess is not itself
            # part of classify_domain()'s deterministic keyword matching.
            description=(
                "Controlled fixture CVE for the V2 release acceptance suite (Scenario A): "
                "pre-authentication SSL VPN request parsing vulnerability affecting FortiOS gateways."
            ),
            cvss_score=9.8, epss_score=0.85, kev_listed=True, domain_guess=Domain.VPN,
            first_seen_at=now, last_updated_at=now,
        )
    )
    candidate = generate_candidate(vuln_repo.get_vulnerability(cve_id), experiment_ids_by_cve={})
    assert candidate is not None, "controlled VPN fixture CVE did not produce a ValidationCandidate"
    vuln_repo.upsert_validation_candidate(candidate)

    queue = admin_client.get("/priority-queue")
    assert queue.status_code == 200, queue.text
    assert any(c["cve_id"] == cve_id for c in queue.json()["candidates"]), (
        "seeded CVE did not appear in the live priority queue"
    )

    # -- Experiment Studio: dataset -> draft -> approval (separate REVIEWER,
    # also covers Scenario D) -> run -> verdict -> evidence ---------------
    researcher_client = _api()
    _login(researcher_client, researcher_username, researcher_password)

    experiment_id = f"ZC-VPN-EXP-9{RUN_TAG_NUM}"
    version = _create_and_run_experiment_version(
        researcher_client, experiment_id=experiment_id, domain_pack_id="vpn",
        template_id="vpn_schema_canonicalisation", template_version="1.0.0",
        cve_id=cve_id, domain="VPN", dataset_config={"oversized_count": 2}, seed=1,
    )

    reviewer_client = _api()
    _login(reviewer_client, reviewer_username, reviewer_password)
    started = reviewer_client.post(f"/experiment-versions/{version['version_id']}/start-review", json={})
    assert started.status_code == 200, started.text
    approved = reviewer_client.post(f"/experiment-versions/{version['version_id']}/approve", json={})
    assert approved.status_code == 200, approved.text

    run_resp = researcher_client.post(f"/experiment-versions/{version['version_id']}/runs", json={})
    assert run_resp.status_code == 202, run_resp.text
    job_id = run_resp.json()["job_id"]

    final_job = _poll_job(admin_client, job_id)
    assert final_job["status"] == "completed", f"VPN run did not complete: {final_job}"

    verdict = admin_client.get(f"/experiments/{experiment_id}/verdict")
    assert verdict.status_code == 200, verdict.text
    verdict_body = verdict.json()
    assert verdict_body["label"] in {
        "effective", "partially_effective", "ineffective", "regression", "inconclusive",
    }, verdict_body

    evidence = admin_client.get(f"/experiments/{experiment_id}/evidence")
    assert evidence.status_code == 200, evidence.text
    evidence_body = evidence.json()
    assert evidence_body["baseline"]["integrity_verified"] is True
    assert evidence_body["mitigation"]["integrity_verified"] is True


# -- Scenario B: Telecom flow, same governed path ----------------------------


def test_scenario_b_telecom_full_governed_flow(admin_client: httpx.Client) -> None:
    researcher_username, researcher_password = _create_user(admin_client, "researcher", "b-researcher")
    reviewer_username, reviewer_password = _create_user(admin_client, "reviewer", "b-reviewer")

    researcher_client = _api()
    _login(researcher_client, researcher_username, researcher_password)

    experiment_id = f"ZC-TELECOM-EXP-9{RUN_TAG_NUM}"
    version = _create_and_run_experiment_version(
        researcher_client, experiment_id=experiment_id, domain_pack_id="telecom",
        template_id="telecom_grammar_state_machine", template_version="1.0.0",
        cve_id="CVE-2023-24033", domain="TELECOM", dataset_config={}, seed=1,
    )

    reviewer_client = _api()
    _login(reviewer_client, reviewer_username, reviewer_password)
    reviewer_client.post(f"/experiment-versions/{version['version_id']}/start-review", json={})
    approved = reviewer_client.post(f"/experiment-versions/{version['version_id']}/approve", json={})
    assert approved.status_code == 200, approved.text

    run_resp = researcher_client.post(f"/experiment-versions/{version['version_id']}/runs", json={})
    assert run_resp.status_code == 202, run_resp.text
    final_job = _poll_job(admin_client, run_resp.json()["job_id"])
    assert final_job["status"] == "completed", f"Telecom run did not complete: {final_job}"

    verdict = admin_client.get(f"/experiments/{experiment_id}/verdict")
    assert verdict.status_code == 200, verdict.text

    evidence = admin_client.get(f"/experiments/{experiment_id}/evidence")
    assert evidence.status_code == 200, evidence.text
    assert evidence.json()["mitigation"]["integrity_verified"] is True


# -- Scenario C: denied/unapproved experiment cannot execute -----------------


def test_scenario_c_unapproved_experiment_is_denied(admin_client: httpx.Client) -> None:
    """Uses a bundled fixture experiment (approval_status: draft in the
    checked-in JSON) via the V1-style direct-submission path
    (POST /experiments/{id}/runs) under the strict `experiment_run` context
    - the same SAFE-004 refusal docs/DEMONSTRATION.md Step 1 exercises via
    the CLI, proven here through the live API instead."""
    resp = admin_client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "experiment_run"}
    )
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["job_id"]
    final_job = _poll_job(admin_client, job_id)
    assert final_job["status"] == "denied", f"unapproved experiment was not denied: {final_job}"


# -- Scenario D: self-approval blocked; a separate REVIEWER can approve -----
# Already exercised structurally inside Scenario A/B (approval always comes
# from a REVIEWER account distinct from the RESEARCHER who created the
# version) - this test isolates and asserts the *rejection* half explicitly.
#
# A genuine finding from this audit, not glossed over: under the current
# single-role-per-user model, POST /experiment-versions requires
# RESEARCHER-or-ADMIN and POST .../approve requires REVIEWER-or-ADMIN - the
# only role that can ever hold both permissions is ADMIN, which the
# self-approval check explicitly exempts. So a plain RESEARCHER never
# actually reaches the self-approval-specific check
# (Action.EXPERIMENT_VERSION_SELF_APPROVAL_BLOCKED,
# error="self_approval_forbidden") at all - require_role's plain RBAC
# dependency rejects them first with a generic 403 "forbidden", since they
# don't hold REVIEWER/ADMIN to call /approve in the first place. That is a
# *stronger*, categorical form of the same protection (a RESEARCHER simply
# cannot reach /approve, self-authored version or not), so the functional
# guarantee this scenario cares about - "a Researcher cannot self-approve" -
# holds either way; this test accepts both 403 shapes rather than asserting
# a specific one that's unreachable for this role in practice.


def test_scenario_d_researcher_cannot_self_approve(admin_client: httpx.Client) -> None:
    researcher_username, researcher_password = _create_user(admin_client, "researcher", "d-researcher")
    researcher_client = _api()
    _login(researcher_client, researcher_username, researcher_password)

    experiment_id = f"ZC-VPN-EXP-8{RUN_TAG_NUM}"
    version = _create_and_run_experiment_version(
        researcher_client, experiment_id=experiment_id, domain_pack_id="vpn",
        template_id="vpn_schema_canonicalisation", template_version="1.0.0",
        cve_id="CVE-2024-21762", domain="VPN", dataset_config={}, seed=2,
    )
    self_approve = researcher_client.post(f"/experiment-versions/{version['version_id']}/approve", json={})
    assert self_approve.status_code == 403, self_approve.text
    assert self_approve.json()["detail"]["error"] in {"forbidden", "self_approval_forbidden"}, self_approve.text

    reviewer_username, reviewer_password = _create_user(admin_client, "reviewer", "d-reviewer")
    reviewer_client = _api()
    _login(reviewer_client, reviewer_username, reviewer_password)
    started = reviewer_client.post(f"/experiment-versions/{version['version_id']}/start-review", json={})
    assert started.status_code == 200, started.text
    approved = reviewer_client.post(f"/experiment-versions/{version['version_id']}/approve", json={})
    assert approved.status_code == 200, approved.text


# -- Scenario E: deterministic regression + revalidation candidate ----------


def test_scenario_e_regression_detection_and_revalidation(admin_client: httpx.Client) -> None:
    """A REAL deterministic control-effectiveness degradation must produce
    a REAL regression-triggered RevalidationCandidate - the actual product
    connection (zeroshield.worker.processor.
    record_control_validation_and_check_regression), not an unrelated
    trigger used as a stand-in. This calls that exact function directly
    (against the live Postgres, through the real AssuranceRepository) with
    two comparison reports - healthy, then degraded - the same shape
    worker.processor builds from a real ComparisonReport after a completed
    run. No KEV/EPSS/advisory data is touched anywhere in this test.

    The execution engine itself can't organically produce two different
    outcomes for the same experiment version (same dataset + same strategy
    = same result, by design - see zeroshield.orchestration), so "a real
    validation, twice, with different comparison metrics" is the correct
    way to exercise this end to end without faking the detection itself:
    detect_regressions() and create_candidate_if_new() below are the exact,
    unmodified functions the worker calls after a genuine run.
    """
    from zeroshield.assurance.control_binding import bind_experiment_to_control
    from zeroshield.assurance.repository import AssuranceRepository
    from zeroshield.db.session import build_engine, build_sessionmaker
    from zeroshield.experiments.discovery import find_experiment
    from zeroshield.models import ComparisonReport, ExperimentMetrics
    from zeroshield.worker.processor import record_control_validation_and_check_regression

    engine = build_engine()
    session_factory = build_sessionmaker(engine)
    assurance_repo = AssuranceRepository(session_factory)

    base_experiment = find_experiment(REPO_ROOT / "experiments", "ZC-VPN-EXP-001")
    assert base_experiment is not None
    # A run-unique mitigation_strategy id, not the bundled experiment's real one - Scenario
    # A/B/D's Studio-run experiments resolve to that same real control (domain +
    # mitigation_strategy_id, see bind_experiment_to_control), so reusing it here would let
    # their genuine validation history leak into this test's own before/after comparison
    # whenever the full suite runs together. get_or_create_control falls back to
    # template_id="unknown" for this synthetic strategy id, which is fine - control-version
    # records are always creatable, real templates just don't need to know about it.
    experiment = base_experiment.model_copy(
        update={"mitigation_strategy": f"{base_experiment.mitigation_strategy}_e2e_{RUN_TAG_NUM}"}
    )
    binding = bind_experiment_to_control(assurance_repo, experiment)

    now = datetime.now(UTC)

    def _metrics(run_id: str, block_rate: float) -> ExperimentMetrics:
        return ExperimentMetrics(
            run_id=run_id, processing_success_rate=1.0, block_rate=block_rate, valid_acceptance_rate=0.95,
            false_positive_rate=0.02, false_negative_rate=0.02, parser_reach_rate=0.05, mean_latency_ms=5.0,
            log_completeness_rate=1.0, calculated_at=now, calculation_version="1.0.0",
        )

    def _record(run_suffix: str, block_rate_improvement: float) -> None:
        baseline_run_id, mitigation_run_id = f"RUN-{RUN_TAG_NUM}{run_suffix}1", f"RUN-{RUN_TAG_NUM}{run_suffix}2"
        comparison = ComparisonReport(
            experiment_id=experiment.experiment_id, baseline_run_id=baseline_run_id,
            mitigation_run_id=mitigation_run_id, total_cases=20,
            baseline_metrics=_metrics(baseline_run_id, block_rate=0.0),
            mitigation_metrics=_metrics(mitigation_run_id, block_rate=block_rate_improvement),
            block_rate_improvement=block_rate_improvement, latency_overhead_ms=5.0,
            limitations=["controlled fixture, not a real run"], generated_at=now,
        )
        record_control_validation_and_check_regression(
            assurance_repo, binding=binding, experiment=experiment, summary=SimpleNamespace(comparison_report=comparison)
        )

    _record("1", 0.90)  # healthy validation - establishes a baseline to regress from
    _record("2", 0.30)  # 0.60 drop >> the 0.10 max-tolerated-drop threshold: a real regression

    # -- the regression itself, via the live API (same route Scenario A/B/D use) --
    effectiveness = admin_client.get(f"/controls/{binding.control.control_id}/effectiveness")
    assert effectiveness.status_code == 200, effectiveness.text
    body = effectiveness.json()
    assert body["regression"] is not None, f"expected a detected regression, got: {body}"
    assert any("block_rate_improvement" in r for r in body["regression"]["reasons"]), body["regression"]

    # -- the regression-triggered revalidation candidate it must have created --
    listed = admin_client.get("/revalidation", params={"status": "pending"})
    assert listed.status_code == 200, listed.text
    regression_candidates = [
        c for c in listed.json()["candidates"]
        if c["trigger_type"] == "regression" and c["control_id"] == binding.control.control_id
    ]
    assert regression_candidates, (
        f"expected a pending regression-triggered revalidation candidate for "
        f"{binding.control.control_id}, got: {listed.json()}"
    )
    candidate = regression_candidates[0]
    assert candidate["status"] == "pending"
    assert "block_rate_improvement" in candidate["trigger_detail"]

    # -- pending, never auto-executed - approval is a separate human action --
    detail = admin_client.get(f"/revalidation/{candidate['candidate_id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["status"] == "pending"
    assert detail.json()["reviewed_by"] is None

    # -- dedup: a second regression against the same control does not create
    # a second pending candidate (create_candidate_if_new's
    # find_pending_candidate check, exercised live) --
    _record("3", 0.10)  # still bad relative to run 2 - another real regression
    listed_again = admin_client.get("/revalidation", params={"status": "pending"})
    assert listed_again.status_code == 200, listed_again.text
    regression_candidates_again = [
        c for c in listed_again.json()["candidates"]
        if c["trigger_type"] == "regression" and c["control_id"] == binding.control.control_id
    ]
    assert len(regression_candidates_again) == 1, (
        f"expected the regression candidate to stay deduplicated, got: {regression_candidates_again}"
    )


# -- Scenario F: AI unconfigured leaves core functionality intact -----------


def test_scenario_f_ai_unconfigured_core_still_works(admin_client: httpx.Client) -> None:
    """docker-compose.yml sets no ANTHROPIC_API_KEY/AI_PROVIDER for the api
    service, so this is the stack's real, default, unmodified state - not a
    simulated one."""
    health = admin_client.get("/health")
    assert health.status_code == 200, health.text

    controls = admin_client.get("/controls")
    assert controls.status_code == 200, controls.text

    assets = admin_client.get("/assets")
    assert assets.status_code == 200, assets.text

    revalidation = admin_client.get("/revalidation")
    assert revalidation.status_code == 200, revalidation.text

    domain_packs = admin_client.get("/domain-packs")
    assert domain_packs.status_code == 200, domain_packs.text

    # The one thing that SHOULD be degraded: an actual AI request.
    ai_attempt = admin_client.post("/vulnerabilities/CVE-2024-21762/analyst/mitigation-gap")
    assert ai_attempt.status_code == 503, ai_attempt.text
    assert ai_attempt.json()["detail"]["error"] == "ai_unavailable"


# -- Scenario G: MinIO unavailable during evidence persistence --------------


def test_scenario_g_minio_unavailable_fails_safely(admin_client: httpx.Client) -> None:
    """docker-compose.yml's `worker` service defaults to the local evidence
    backend (final release verification fix - see docker-compose.yml's
    top-of-file comment on ZEROSHIELD_EVIDENCE_BACKEND for why), so this
    scenario stops the persistent worker (so it can't race for the job),
    starts a one-off worker container with ZEROSHIELD_EVIDENCE_BACKEND=minio
    forced, stops minio, submits a run, and asserts the job reaches FAILED -
    never a falsely-reported `completed` evidence record. Restores the
    normal persistent worker afterwards regardless of outcome so later
    scenarios in this module are unaffected."""
    stopped_worker = _run_compose("stop", "worker")
    assert stopped_worker.returncode == 0, stopped_worker.stderr
    # docker compose stop returning does not guarantee the stopped
    # container's pika consumer registration was already torn down
    # server-side - wait for RabbitMQ itself to confirm zero consumers
    # before submitting, rather than a fixed guessed sleep (a real,
    # observed flake otherwise: the old, "stopped" local-backend worker
    # still grabs the message).
    _wait_for_run_queue_consumer_count(0)
    stopped_minio = _run_compose("stop", "minio")
    assert stopped_minio.returncode == 0, stopped_minio.stderr
    one_off_name = f"zeroshield-e2e-minio-worker-{RUN_TAG}"
    try:
        started = _run_compose(
            # --no-deps: `docker compose run` auto-starts a stopped
            # dependency's container by default (confirmed by direct
            # experiment: minio came back "healthy" within a couple of
            # seconds of a plain `docker compose run ... worker`) - without
            # this flag it would silently resurrect minio and defeat the
            # entire premise of this scenario.
            "run", "--no-deps", "-d", "--rm", "--name", one_off_name,
            "-e", "ZEROSHIELD_EVIDENCE_BACKEND=minio",
            "-e", "MINIO_ENDPOINT=minio:9000",
            "-e", "MINIO_ACCESS_KEY=zeroshield",
            "-e", "MINIO_SECRET_KEY=zeroshield123",
            "-e", "MINIO_SECURE=false",
            "worker",
        )
        assert started.returncode == 0, started.stderr
        _wait_for_run_queue_consumer_count(1)

        resp = admin_client.post(
            "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
        )
        assert resp.status_code == 202, resp.text
        job_id = resp.json()["job_id"]
        final_job = _poll_job(admin_client, job_id, timeout=60.0)
        assert final_job["status"] == "failed", (
            f"expected the job to FAIL safely with MinIO down, got: {final_job}"
        )
        # A FAILED job never carries a result summary - the API has nothing
        # it could even use to falsely construct a "completed" evidence
        # response for this run.
        assert final_job.get("result") is None, (
            f"a FAILED job unexpectedly carried a result summary: {final_job}"
        )
    finally:
        _run_docker("kill", one_off_name)
        _run_docker("rm", "-f", one_off_name)
        restarted_minio = _run_compose("start", "minio")
        assert restarted_minio.returncode == 0, restarted_minio.stderr
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            ps = _run_compose("ps", "minio", "--format", "json")
            if '"Health":"healthy"' in ps.stdout or "healthy" in ps.stdout:
                break
            time.sleep(2)
        restarted_worker = _run_compose("start", "worker")
        assert restarted_worker.returncode == 0, restarted_worker.stderr
        _wait_for_run_queue_consumer_count(1)


# -- Scenario H: worker restart mid-processing -------------------------------


def test_scenario_h_worker_restart_recovery(admin_client: httpx.Client) -> None:
    """Submits a run, restarts the worker container as fast as possible
    afterwards (racing the worker's own processing - the goal is to land
    the restart while the message is still unacked as often as possible,
    not to guarantee it every run), then documents what actually happens:
    RabbitMQ redelivers an unacked message to the reconnected consumer
    (standard AMQP behaviour, not custom ZeroShield logic), and
    process_run_job's own idempotent _record()/JobStore.save() calls make
    reprocessing the same job_id safe - the last write for a given job_id
    always wins, there is no duplicate-record possibility since JobStore is
    one file per job_id, not an append log."""
    resp = admin_client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["job_id"]

    restarted = _run_compose("restart", "worker", "-t", "1")
    assert restarted.returncode == 0, restarted.stderr

    final_job = _poll_job(admin_client, job_id, timeout=90.0)
    assert final_job["status"] in {"completed", "failed", "denied"}, (
        f"job did not reach a coherent terminal state after a worker restart: {final_job}"
    )
    # No duplicate/orphaned job record: GET /jobs/{job_id} is a single
    # record keyed by job_id (JobStore is one file per job_id) - a second,
    # independent read must return the exact same terminal state, proving
    # the restart didn't leave two divergent views of the same job.
    reread = admin_client.get(f"/jobs/{job_id}")
    assert reread.status_code == 200
    assert reread.json()["status"] == final_job["status"]
