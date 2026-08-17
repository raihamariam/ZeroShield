"""Tests the /assets and /vulnerabilities/{cve_id}/affected-assets routes
(V2 Phase 5, Step 7) against a real in-memory-SQLite-backed
AssuranceRepository/VulnerabilityRepository - no live Postgres. Closes the
HTTP-level test gap flagged in the Phase 5 audit: these routers were
mounted and reachable but had zero direct request/response coverage.
"""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.db.base import Base
from zeroshield.intelligence.repository import VulnerabilityRepository


@pytest.fixture
def _session_factory():
    # AssuranceRepository and VulnerabilityRepository share one PostgreSQL
    # database in production (both are just SQLAlchemy repos over the same
    # DATABASE_URL) - list_potentially_affected_assets joins assurance's
    # AssetORM against intelligence's ProductORM/AffectedProductORM tables
    # directly, so the two repos MUST share one engine here too, or the join
    # silently sees an empty products table.
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def assurance_repo(_session_factory) -> AssuranceRepository:
    return AssuranceRepository(_session_factory)


@pytest.fixture
def vuln_repo(_session_factory) -> VulnerabilityRepository:
    return VulnerabilityRepository(_session_factory)


@pytest.fixture
def client(assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository) -> Iterator[TestClient]:
    app.dependency_overrides[dependencies.get_assurance_repository] = lambda: assurance_repo
    app.dependency_overrides[dependencies.get_vulnerability_repository] = lambda: vuln_repo
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _asset_payload(**overrides: object) -> dict:
    payload = {
        "asset_id": "ASSET-1", "name": "Edge VPN concentrator", "vendor": "fortinet", "product": "FortiOS",
        "version": "7.0.1", "environment": "production", "exposure": "internet_facing", "criticality": "high",
    }
    payload.update(overrides)
    return payload


def test_create_and_get_asset(client: TestClient) -> None:
    response = client.post("/assets", json=_asset_payload())
    assert response.status_code == 201
    assert response.json()["asset_id"] == "ASSET-1"

    fetched = client.get("/assets/ASSET-1")
    assert fetched.status_code == 200
    assert fetched.json()["vendor"] == "fortinet"


def test_create_asset_duplicate_id_is_409(client: TestClient) -> None:
    client.post("/assets", json=_asset_payload())
    response = client.post("/assets", json=_asset_payload())
    assert response.status_code == 409


def test_get_unknown_asset_is_404(client: TestClient) -> None:
    assert client.get("/assets/does-not-exist").status_code == 404


def test_list_assets_filters_by_active_and_vendor(client: TestClient) -> None:
    client.post("/assets", json=_asset_payload(asset_id="ASSET-1", vendor="fortinet"))
    client.post("/assets", json=_asset_payload(asset_id="ASSET-2", vendor="ivanti"))
    client.patch("/assets/ASSET-2", json={"active": False})

    active_only = client.get("/assets", params={"active": True})
    assert {a["asset_id"] for a in active_only.json()["assets"]} == {"ASSET-1"}

    fortinet_only = client.get("/assets", params={"vendor": "fortinet"})
    assert {a["asset_id"] for a in fortinet_only.json()["assets"]} == {"ASSET-1"}


def test_update_unknown_asset_is_404(client: TestClient) -> None:
    response = client.patch("/assets/does-not-exist", json={"active": False})
    assert response.status_code == 404


def test_affected_assets_matches_by_vendor_and_product_deterministically(
    client: TestClient, vuln_repo: VulnerabilityRepository
) -> None:
    """Step 7: 'link vulnerabilities to potentially affected assets using
    deterministic rules' - never AI. Seeds real products/affected_products
    rows the same way NVD ingestion would."""
    from zeroshield.models.vulnerability import Vulnerability

    now = datetime.now(UTC)
    vuln_repo.upsert_vulnerability(Vulnerability(cve_id="CVE-2024-21762", first_seen_at=now, last_updated_at=now))
    vuln_repo.upsert_products("CVE-2024-21762", [("fortinet", "FortiOS", None)])

    client.post("/assets", json=_asset_payload(asset_id="ASSET-1", vendor="fortinet", product="FortiOS SSL-VPN"))
    client.post("/assets", json=_asset_payload(asset_id="ASSET-2", vendor="ivanti", product="Connect Secure"))

    response = client.get("/vulnerabilities/CVE-2024-21762/affected-assets")
    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == "CVE-2024-21762"
    assert [a["asset_id"] for a in body["assets"]] == ["ASSET-1"]


def test_affected_assets_with_no_product_match_is_empty(client: TestClient) -> None:
    response = client.get("/vulnerabilities/CVE-2024-99999/affected-assets")
    assert response.status_code == 200
    assert response.json()["assets"] == []
