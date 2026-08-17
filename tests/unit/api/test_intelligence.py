"""Tests the /vulnerabilities, /priority-queue, /sources, /integrations, and
/intelligence/* routes against a real in-memory-SQLite-backed
VulnerabilityRepository (dependency-overridden, like get_publisher elsewhere
in this test suite) - no live network, no live Postgres.
"""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from tests.unit.api.conftest import fake_user

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.audit.repository import AuditRepository
from zeroshield.db.base import Base
from zeroshield.intelligence.connectors.base import RawIntelligenceRecord
from zeroshield.intelligence.dedup import merge
from zeroshield.intelligence.messaging import IntelligenceSyncJobMessage
from zeroshield.intelligence.normalisation import normalise
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.models.vulnerability import VulnerabilitySourceName


@pytest.fixture
def vuln_repo() -> VulnerabilityRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return VulnerabilityRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def published_sync_messages() -> list[IntelligenceSyncJobMessage]:
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
    vuln_repo: VulnerabilityRepository, published_sync_messages: list[IntelligenceSyncJobMessage],
    audit_repo: AuditRepository,
) -> Iterator[TestClient]:
    app.dependency_overrides[dependencies.get_vulnerability_repository] = lambda: vuln_repo
    app.dependency_overrides[dependencies.get_intelligence_publisher] = lambda: published_sync_messages.append
    app.dependency_overrides[dependencies.get_audit_repository] = lambda: audit_repo
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _seed_vulnerability(vuln_repo: VulnerabilityRepository, cve_id: str = "CVE-2024-21762") -> None:
    raw = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": "FortiOS SSL VPN out-of-bound write"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.6, "vectorString": "x", "version": "3.1"}}]},
        "weaknesses": [], "references": [],
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:fortinet:fortios:*"}]}]}],
    }
    contribution = normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id=cve_id, raw=raw))
    result = merge(None, contribution)
    vuln_repo.upsert_vulnerability(result.vulnerability)
    vuln_repo.upsert_source_record(result.source_record)
    vuln_repo.append_history(result.history)


def test_list_vulnerabilities_without_database_url_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with TestClient(app, raise_server_exceptions=False) as client_no_override:
        response = client_no_override.get("/vulnerabilities")
    assert response.status_code == 503
    assert response.json()["detail"]["error"] == "intelligence_unavailable"


def test_list_vulnerabilities_empty(client: TestClient) -> None:
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert response.json() == {"vulnerabilities": [], "total": 0, "limit": 50, "offset": 0}


def test_list_vulnerabilities_returns_seeded_record(client: TestClient, vuln_repo: VulnerabilityRepository) -> None:
    _seed_vulnerability(vuln_repo)
    response = client.get("/vulnerabilities")
    body = response.json()
    assert body["total"] == 1
    assert body["vulnerabilities"][0]["cve_id"] == "CVE-2024-21762"
    assert body["vulnerabilities"][0]["cvss_score"] == 9.6


def test_list_vulnerabilities_filters_by_cvss_gte(client: TestClient, vuln_repo: VulnerabilityRepository) -> None:
    _seed_vulnerability(vuln_repo)
    assert client.get("/vulnerabilities", params={"cvss_gte": 9.0}).json()["total"] == 1
    assert client.get("/vulnerabilities", params={"cvss_gte": 9.9}).json()["total"] == 0


def test_list_vulnerabilities_rejects_out_of_range_filter(client: TestClient) -> None:
    response = client.get("/vulnerabilities", params={"cvss_gte": 20.0})
    assert response.status_code == 422


def test_get_vulnerability_detail_returns_source_records(client: TestClient, vuln_repo: VulnerabilityRepository) -> None:
    _seed_vulnerability(vuln_repo)
    response = client.get("/vulnerabilities/CVE-2024-21762")
    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == "CVE-2024-21762"
    assert len(body["source_records"]) == 1
    assert body["source_records"][0]["source"] == "nvd"


def test_get_vulnerability_detail_unknown_returns_404(client: TestClient) -> None:
    response = client.get("/vulnerabilities/CVE-2024-21762")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "vulnerability_not_found"


def test_get_vulnerability_detail_rejects_malformed_cve_id(client: TestClient) -> None:
    response = client.get("/vulnerabilities/not-a-cve")
    assert response.status_code == 422


def test_get_vulnerability_history_returns_entries(client: TestClient, vuln_repo: VulnerabilityRepository) -> None:
    _seed_vulnerability(vuln_repo)
    response = client.get("/vulnerabilities/CVE-2024-21762/history")
    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == "CVE-2024-21762"
    assert len(body["history"]) >= 1


def test_priority_queue_empty(client: TestClient) -> None:
    assert client.get("/priority-queue").json() == {"candidates": [], "total": 0, "limit": 50, "offset": 0}


def test_sources_lists_registered_connectors(client: TestClient) -> None:
    response = client.get("/sources")
    assert response.status_code == 200
    sources = {s["source"] for s in response.json()["sources"]}
    assert sources == {"nvd", "cisa_kev", "epss", "github_advisory"}


def test_integrations_is_alias_of_sources(client: TestClient) -> None:
    sources_resp = client.get("/sources").json()
    integrations_resp = client.get("/integrations").json()
    assert {s["source"] for s in sources_resp["sources"]} == {s["source"] for s in integrations_resp["sources"]}


def test_submit_sync_returns_202_and_publishes(
    client: TestClient, published_sync_messages: list[IntelligenceSyncJobMessage]
) -> None:
    response = client.post("/intelligence/sync", json={"source": "nvd"})
    assert response.status_code == 202
    body = response.json()
    assert body["source"] == "nvd"
    assert body["status"] == "queued"
    assert body["sync_id"].startswith("SYNC-")
    assert len(published_sync_messages) == 1
    assert published_sync_messages[0].source is VulnerabilitySourceName.NVD


def test_submit_sync_records_queued_status_immediately(
    client: TestClient, vuln_repo: VulnerabilityRepository
) -> None:
    response = client.post("/intelligence/sync", json={"source": "cisa_kev"})
    sync_id = response.json()["sync_id"]
    status_response = client.get(f"/intelligence/syncs/{sync_id}")
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "queued"


def test_submit_sync_with_since_parses_iso_timestamp(
    client: TestClient, published_sync_messages: list[IntelligenceSyncJobMessage]
) -> None:
    response = client.post("/intelligence/sync", json={"source": "nvd", "since": "2024-01-01T00:00:00+00:00"})
    assert response.status_code == 202
    assert published_sync_messages[0].since == datetime(2024, 1, 1, tzinfo=UTC)


def test_submit_sync_unknown_source_returns_422(client: TestClient) -> None:
    response = client.post("/intelligence/sync", json={"source": "not_a_real_source"})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "unknown_source"


def test_submit_sync_manual_import_source_returns_422(client: TestClient) -> None:
    """manual_import is a valid VulnerabilitySourceName but has no connector -
    never syncable, only import_and_merge()-able."""
    response = client.post("/intelligence/sync", json={"source": "manual_import"})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "unregistered_source"


def test_submit_sync_invalid_since_returns_422(client: TestClient) -> None:
    response = client.post("/intelligence/sync", json={"source": "nvd", "since": "not-a-date"})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "invalid_since"


def test_submit_sync_rejects_unexpected_fields(client: TestClient) -> None:
    response = client.post("/intelligence/sync", json={"source": "nvd", "extra_field": "x"})
    assert response.status_code == 422


def test_get_sync_status_unknown_returns_404(client: TestClient) -> None:
    response = client.get("/intelligence/syncs/SYNC-" + "0" * 32)
    assert response.status_code == 404


def test_get_sync_status_rejects_malformed_id(client: TestClient) -> None:
    response = client.get("/intelligence/syncs/not-a-valid-id")
    assert response.status_code == 422


def test_list_syncs_returns_submitted_syncs(client: TestClient) -> None:
    client.post("/intelligence/sync", json={"source": "nvd"})
    client.post("/intelligence/sync", json={"source": "epss"})
    response = client.get("/intelligence/syncs")
    assert response.status_code == 200
    assert len(response.json()["syncs"]) == 2
