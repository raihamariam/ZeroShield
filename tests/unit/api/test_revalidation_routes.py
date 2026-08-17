"""Tests /revalidation routes (V2 Phase 5, Step 11) against a real
in-memory-SQLite-backed AssuranceRepository/VulnerabilityRepository - no
live Postgres. Closes the HTTP-level test gap flagged in the Phase 5 audit,
and specifically asserts the flow the phase brief requires: trigger -> scan
creates a *pending* candidate -> approve only flips status, never itself
queues or executes a run.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from tests.unit.api.conftest import fake_user

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.assurance.models import ControlValidation
from zeroshield.assurance.repository import AssuranceRepository, control_id_for
from zeroshield.audit.repository import AuditRepository
from zeroshield.db.base import Base
from zeroshield.intelligence.repository import VulnerabilityRepository

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
NOW = datetime.now(UTC)
CONTROL_ID = control_id_for("VPN", "strict_schema_canonicalisation_mitigation")


@pytest.fixture
def assurance_repo() -> AssuranceRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AssuranceRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def vuln_repo() -> VulnerabilityRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return VulnerabilityRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def audit_repo() -> AuditRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AuditRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def client(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository, audit_repo: AuditRepository
) -> Iterator[TestClient]:
    app.dependency_overrides[dependencies.get_assurance_repository] = lambda: assurance_repo
    app.dependency_overrides[dependencies.get_vulnerability_repository] = lambda: vuln_repo
    app.dependency_overrides[dependencies.get_experiments_dir] = lambda: EXPERIMENTS_DIR
    app.dependency_overrides[dependencies.get_audit_repository] = lambda: audit_repo
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _seed_stale_control(assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(
        domain="VPN", mitigation_strategy_id="strict_schema_canonicalisation_mitigation", name="X"
    )
    version = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn",
        template_id="vpn_schema_canonicalisation", template_version="1.0.0",
    )
    assurance_repo.record_validation(
        ControlValidation(
            validation_id="VAL-1", control_id=control.control_id, version_id=version.version_id,
            experiment_id="ZC-VPN-EXP-001", baseline_run_id="RUN-1", mitigation_run_id="RUN-2", total_cases=10,
            block_rate_improvement=0.6, false_positive_rate=0.0, false_negative_rate=0.0,
            valid_acceptance_rate=1.0, parser_reach_rate=0.0, latency_overhead_ms=1.0, verdict_label="effective",
            validated_at=NOW - timedelta(days=200),
        )
    )


def test_scan_creates_pending_candidates_never_executes_anything(
    client: TestClient, assurance_repo: AssuranceRepository
) -> None:
    _seed_stale_control(assurance_repo)
    response = client.post("/revalidation/scan")
    assert response.status_code == 200
    body = response.json()
    assert body["controls_scanned"] == 1
    scheduled = [c for c in body["candidates_created"] if c["trigger_type"] == "scheduled"]
    assert len(scheduled) == 1
    assert scheduled[0]["status"] == "pending"


def test_scan_never_creates_duplicate_pending_candidates_via_api(
    client: TestClient, assurance_repo: AssuranceRepository
) -> None:
    _seed_stale_control(assurance_repo)
    client.post("/revalidation/scan")
    second = client.post("/revalidation/scan")
    assert second.json()["candidates_created"] == []
    pending = client.get("/revalidation", params={"status": "pending"}).json()["candidates"]
    scheduled = [c for c in pending if c["trigger_type"] == "scheduled" and c["control_id"] == CONTROL_ID]
    assert len(scheduled) == 1


def test_approve_only_flips_status_never_queues_a_run(client: TestClient, assurance_repo: AssuranceRepository) -> None:
    _seed_stale_control(assurance_repo)
    scan_response = client.post("/revalidation/scan")
    candidate_id = scan_response.json()["candidates_created"][0]["candidate_id"]

    response = client.post(f"/revalidation/{candidate_id}/approve", json={"note": "go ahead"})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "approved"
    assert body["reviewed_by"] == fake_user().username
    # Nothing beyond the status/review fields changed - no job_id, no run reference
    # was fabricated by this endpoint.
    assert set(body.keys()) == {
        "candidate_id", "control_id", "experiment_id", "trigger_type", "trigger_detail", "status",
        "created_at", "reviewed_by", "reviewed_at", "review_note",
    }


def test_approving_an_already_resolved_candidate_is_409(client: TestClient, assurance_repo: AssuranceRepository) -> None:
    _seed_stale_control(assurance_repo)
    candidate_id = client.post("/revalidation/scan").json()["candidates_created"][0]["candidate_id"]
    client.post(f"/revalidation/{candidate_id}/approve", json={})
    second = client.post(f"/revalidation/{candidate_id}/approve", json={})
    assert second.status_code == 409


def test_manually_created_candidate_requires_a_known_control(client: TestClient) -> None:
    response = client.post(
        "/revalidation",
        json={"control_id": "does-not-exist", "trigger_type": "new_related_cve", "trigger_detail": "d"},
    )
    assert response.status_code == 404


def test_dismiss_candidate(client: TestClient, assurance_repo: AssuranceRepository) -> None:
    _seed_stale_control(assurance_repo)
    candidate_id = client.post("/revalidation/scan").json()["candidates_created"][0]["candidate_id"]
    response = client.post(f"/revalidation/{candidate_id}/dismiss", json={"note": "not needed"})
    assert response.status_code == 200
    assert response.json()["status"] == "dismissed"
