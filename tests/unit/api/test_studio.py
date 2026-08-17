"""Tests /domain-packs, /templates, /datasets/generate, /experiment-versions,
approval routes, and /experiments/{id}/verdict against a real in-memory
SQLite-backed ExperimentVersionRepository - no live Postgres/RabbitMQ.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from tests.unit.api.conftest import fake_user

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role
from zeroshield.db.base import Base
from zeroshield.services.job_store import RunJobMessage
from zeroshield.studio.repository import ExperimentVersionRepository

REPO_ROOT = Path(__file__).resolve().parents[3]
VPN_CVE_PAYLOAD = {
    "cve_id": "CVE-2024-21762", "domain": "VPN", "cvss_score": 9.8, "cisa_kev": True, "epss_score": 0.83,
    "trust_boundary": "x", "root_cause": "memory_safety_failure", "vendor_mitigation": "x",
    "mitigation_gap": "x", "source_urls": ["https://example.com"], "retrieved_date": "2026-07-13",
}


@pytest.fixture
def version_repo() -> ExperimentVersionRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return ExperimentVersionRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def studio_experiments_dir(tmp_path: Path) -> Path:
    return tmp_path / "experiments"


@pytest.fixture
def dataset_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Chdir into tmp_path so build_experiment_draft's default relative
    dataset_root resolves cleanly, exactly like tests/unit/studio's autouse
    fixture - the API layer itself always uses the builder's CWD-relative
    default (see routes/studio.py), so this test suite must run from a
    writable directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def published_messages() -> list[RunJobMessage]:
    return []


@pytest.fixture
def audit_repo() -> AuditRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AuditRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def client(
    version_repo: ExperimentVersionRepository,
    studio_experiments_dir: Path,
    dataset_root: Path,
    published_messages: list[RunJobMessage],
    audit_repo: AuditRepository,
) -> Iterator[TestClient]:
    app.dependency_overrides[dependencies.get_experiment_version_repository] = lambda: version_repo
    app.dependency_overrides[dependencies.get_experiments_dir] = lambda: studio_experiments_dir
    app.dependency_overrides[dependencies.get_results_root] = lambda: dataset_root / "results"
    app.dependency_overrides[dependencies.get_jobs_dir] = lambda: dataset_root / "jobs"
    app.dependency_overrides[dependencies.get_publisher] = lambda: published_messages.append
    app.dependency_overrides[dependencies.get_audit_repository] = lambda: audit_repo
    # ADMIN by default - can create/edit/submit/review/approve/run without ever
    # hitting an RBAC 403, so tests that aren't themselves about RBAC don't need
    # to think about roles. test_self_approval_is_blocked_for_a_researcher below
    # overrides this per-call to exercise the actual role/identity boundaries.
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _create_version_payload(**overrides: object) -> dict:
    payload = {
        "experiment_id": "ZC-VPN-EXP-960", "title": "API test", "description": "desc",
        "related_cves": [VPN_CVE_PAYLOAD], "domain_pack_id": "vpn", "template_id": "vpn_schema_canonicalisation",
        "template_version": "1.0.0", "dataset_config": {"oversized_count": 2, "invalid_path_count": 2},
        "seed": 5, "failure_pattern": "p", "root_cause": "memory_safety_failure", "vendor_mitigation": "x",
        "mitigation_gap": "x", "research_question": "q?", "hypothesis": "h",
    }
    payload.update(overrides)
    return payload


# -- domain packs / templates / dataset generation ---------------------------


def test_list_domain_packs(client: TestClient) -> None:
    response = client.get("/domain-packs")
    assert response.status_code == 200
    ids = {p["pack_id"] for p in response.json()["domain_packs"]}
    assert ids == {"vpn", "telecom"}


def test_list_domain_pack_templates(client: TestClient) -> None:
    response = client.get("/domain-packs/vpn/templates")
    assert response.status_code == 200
    assert response.json()["templates"][0]["template_id"] == "vpn_schema_canonicalisation"


def test_list_templates_unknown_domain_pack_404(client: TestClient) -> None:
    response = client.get("/domain-packs/does-not-exist/templates")
    assert response.status_code == 404


def test_get_template(client: TestClient) -> None:
    response = client.get("/templates/vpn_schema_canonicalisation/1.0.0")
    assert response.status_code == 200
    assert response.json()["allowed_mitigation_strategies"] == ["strict_schema_canonicalisation_mitigation"]


def test_get_template_unknown_version_404(client: TestClient) -> None:
    response = client.get("/templates/vpn_schema_canonicalisation/99.0.0")
    assert response.status_code == 404


def test_generate_dataset_preview_is_deterministic(client: TestClient) -> None:
    body = {"domain_pack_id": "vpn", "seed": 5, "config": {"oversized_count": 2}}
    r1 = client.post("/datasets/generate", json=body)
    r2 = client.post("/datasets/generate", json=body)
    assert r1.status_code == 200
    assert r1.json()["sha256"] == r2.json()["sha256"]


def test_generate_dataset_invalid_config_returns_422(client: TestClient) -> None:
    response = client.post(
        "/datasets/generate", json={"domain_pack_id": "vpn", "seed": 5, "config": {"valid_count": -1}}
    )
    assert response.status_code == 422


def test_generate_dataset_unknown_domain_pack_404(client: TestClient) -> None:
    response = client.post("/datasets/generate", json={"domain_pack_id": "nope", "seed": 1, "config": {}})
    assert response.status_code == 404


# -- experiment versions / approval workflow ---------------------------------


def test_create_experiment_version_201(client: TestClient) -> None:
    response = client.post("/experiment-versions", json=_create_version_payload())
    assert response.status_code == 201
    assert response.json()["status"] == "draft"


def test_create_experiment_version_invalid_template_returns_422(client: TestClient) -> None:
    response = client.post(
        "/experiment-versions", json=_create_version_payload(template_id="does-not-exist")
    )
    assert response.status_code == 422


def test_get_experiment_version(client: TestClient) -> None:
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]
    response = client.get(f"/experiment-versions/{version_id}")
    assert response.status_code == 200
    assert response.json()["version_id"] == version_id


def test_get_experiment_version_404(client: TestClient) -> None:
    assert client.get("/experiment-versions/does-not-exist").status_code == 404


def test_edit_draft_via_api(client: TestClient) -> None:
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]
    response = client.patch(f"/experiment-versions/{version_id}", json={"title": "revised"})
    assert response.status_code == 200
    assert client.get(f"/experiment-versions/{version_id}").json()["version_id"] == version_id


def test_full_approval_workflow_via_api(
    client: TestClient, studio_experiments_dir: Path, published_messages: list[RunJobMessage]
) -> None:
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]

    r = client.post(f"/experiment-versions/{version_id}/submit-review", json={})
    assert r.status_code == 200 and r.json()["status"] == "ready_for_review"

    r = client.post(f"/experiment-versions/{version_id}/start-review", json={})
    assert r.status_code == 200 and r.json()["status"] == "under_review"

    r = client.post(f"/experiment-versions/{version_id}/approve", json={"reason": "ok"})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert (studio_experiments_dir / "ZC-VPN-EXP-960.json").is_file()

    r = client.get(f"/experiment-versions/{version_id}/approvals")
    assert len(r.json()) == 3

    run_response = client.post(f"/experiment-versions/{version_id}/runs")
    assert run_response.status_code == 202
    assert run_response.json()["status"] == "queued"
    assert len(published_messages) == 1
    assert published_messages[0].execution_context.value == "experiment_run"


def test_invalid_transition_returns_409(client: TestClient) -> None:
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]
    response = client.post(f"/experiment-versions/{version_id}/approve", json={})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "invalid_transition"


def test_submit_run_for_non_approved_version_returns_409(client: TestClient) -> None:
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]
    response = client.post(f"/experiment-versions/{version_id}/runs")
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "version_not_approved"


def test_list_experiment_versions_filters(client: TestClient) -> None:
    client.post("/experiment-versions", json=_create_version_payload(experiment_id="ZC-VPN-EXP-961"))
    client.post("/experiment-versions", json=_create_version_payload(experiment_id="ZC-VPN-EXP-962"))
    response = client.get("/experiment-versions", params={"experiment_id": "ZC-VPN-EXP-961"})
    assert len(response.json()["versions"]) == 1


def test_reject_workflow(client: TestClient) -> None:
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]
    client.post(f"/experiment-versions/{version_id}/submit-review", json={})
    client.post(f"/experiment-versions/{version_id}/start-review", json={})
    response = client.post(f"/experiment-versions/{version_id}/reject", json={"reason": "insufficient"})
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"


def test_self_approval_is_blocked_for_a_researcher(client: TestClient) -> None:
    """Step 2: 'Where practical, a Researcher must not approve their own
    experiment.' Enforced on the authenticated actor, never a client-supplied
    name - creates a version as one identity, then attempts to approve it as
    that SAME identity (now holding REVIEWER permissions too, the only way
    the approve route would let them try at all), and confirms it is refused
    even though the role check alone would have allowed it."""
    researcher = fake_user(Role.RESEARCHER, username="dual-role-alice", user_id="USER-alice")
    other_reviewer = fake_user(Role.REVIEWER, username="bob", user_id="USER-bob")
    alice_as_reviewer = fake_user(Role.REVIEWER, username="dual-role-alice", user_id="USER-alice")

    app.dependency_overrides[dependencies.get_current_user] = lambda: researcher
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]
    assert client.post(f"/experiment-versions/{version_id}/submit-review", json={}).status_code == 200

    app.dependency_overrides[dependencies.get_current_user] = lambda: other_reviewer
    assert client.post(f"/experiment-versions/{version_id}/start-review", json={}).status_code == 200

    app.dependency_overrides[dependencies.get_current_user] = lambda: alice_as_reviewer
    blocked = client.post(f"/experiment-versions/{version_id}/approve", json={})
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["error"] == "self_approval_forbidden"

    app.dependency_overrides[dependencies.get_current_user] = lambda: other_reviewer
    approved = client.post(f"/experiment-versions/{version_id}/approve", json={})
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"


def test_researcher_cannot_approve_even_a_different_researchers_version(client: TestClient) -> None:
    """RBAC alone (not just self-approval) must block a RESEARCHER from
    approving anything - approve requires REVIEWER/ADMIN."""
    researcher = fake_user(Role.RESEARCHER, username="alice", user_id="USER-alice")
    another_researcher = fake_user(Role.RESEARCHER, username="carol", user_id="USER-carol")

    app.dependency_overrides[dependencies.get_current_user] = lambda: researcher
    version_id = client.post("/experiment-versions", json=_create_version_payload()).json()["version_id"]
    client.post(f"/experiment-versions/{version_id}/submit-review", json={})

    app.dependency_overrides[dependencies.get_current_user] = lambda: another_researcher
    response = client.post(f"/experiment-versions/{version_id}/start-review", json={})
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "forbidden"


# -- verdict ------------------------------------------------------------------


def test_verdict_404_before_any_run(client: TestClient, studio_experiments_dir: Path) -> None:
    import shutil

    studio_experiments_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(
        REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json", studio_experiments_dir / "ZC-VPN-EXP-001.json"
    )
    response = client.get("/experiments/ZC-VPN-EXP-001/verdict")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_evidence"


def test_verdict_404_for_unknown_experiment(client: TestClient) -> None:
    response = client.get("/experiments/ZC-VPN-EXP-999999/verdict")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "experiment_not_found"


def test_verdict_after_real_run(
    client: TestClient, dataset_root: Path, studio_experiments_dir: Path
) -> None:
    import shutil

    from zeroshield.models import ExperimentDefinition
    from zeroshield.policies import ExecutionContext
    from zeroshield.services import experiment_service

    shutil.copytree(REPO_ROOT / "test_data", dataset_root / "test_data", dirs_exist_ok=True)
    studio_experiments_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(
        REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json", studio_experiments_dir / "ZC-VPN-EXP-001.json"
    )
    experiment = ExperimentDefinition.model_validate_json(
        (REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json").read_text(encoding="utf-8")
    )
    experiment_service.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=dataset_root / "results"
    )

    response = client.get("/experiments/ZC-VPN-EXP-001/verdict")
    assert response.status_code == 200
    body = response.json()
    assert body["label"] == "effective"
    assert len(body["reasons"]) >= 1
    assert len(body["limitations"]) >= 1
