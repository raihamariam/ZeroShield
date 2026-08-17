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
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.repository import AuthRepository
from zeroshield.db.base import Base
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.services.job_store import RunJobMessage
from zeroshield.studio.repository import ExperimentVersionRepository


@pytest.fixture
def results_root(tmp_path: Path) -> Path:
    return tmp_path / "results"


@pytest.fixture
def jobs_dir(tmp_path: Path) -> Path:
    return tmp_path / "jobs"


@pytest.fixture
def published_messages() -> list[RunJobMessage]:
    return []


@pytest.fixture
def db_session_factory():
    """One shared in-memory SQLite engine for every DB-backed repository -
    some routes join across them (e.g. asset<->vulnerability affected-asset
    matching), so they must share a session factory the same way they share
    one PostgreSQL database in production."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def audit_repository(db_session_factory) -> AuditRepository:
    return AuditRepository(db_session_factory)


@pytest.fixture
def auth_repository(db_session_factory) -> AuthRepository:
    return AuthRepository(db_session_factory)


@pytest.fixture
def assurance_repository(db_session_factory) -> AssuranceRepository:
    return AssuranceRepository(db_session_factory)


@pytest.fixture
def vulnerability_repository(db_session_factory) -> VulnerabilityRepository:
    return VulnerabilityRepository(db_session_factory)


@pytest.fixture
def experiment_version_repository(db_session_factory) -> ExperimentVersionRepository:
    return ExperimentVersionRepository(db_session_factory)


@pytest.fixture
def client(
    results_root: Path,
    jobs_dir: Path,
    published_messages: list[RunJobMessage],
    audit_repository: AuditRepository,
    auth_repository: AuthRepository,
    assurance_repository: AssuranceRepository,
    vulnerability_repository: VulnerabilityRepository,
    experiment_version_repository: ExperimentVersionRepository,
) -> Iterator[TestClient]:
    """Same wiring as tests/unit/api/conftest.py's client fixture, extended
    with every DB-backed repository (V2 Phase 6) so any route is reachable -
    this suite covers path-traversal/injection/malformed-input/auth/RBAC
    hardening across the whole API, not just filesystem-backed routes.
    Authenticated as a fixed ADMIN by default; tests that need a different
    (or no) identity override dependencies.get_current_user themselves - see
    tests/security/test_rbac_hardening.py."""
    app.dependency_overrides[dependencies.get_results_root] = lambda: results_root
    app.dependency_overrides[dependencies.get_jobs_dir] = lambda: jobs_dir
    app.dependency_overrides[dependencies.get_publisher] = lambda: published_messages.append
    app.dependency_overrides[dependencies.get_audit_repository] = lambda: audit_repository
    app.dependency_overrides[dependencies.get_auth_repository] = lambda: auth_repository
    app.dependency_overrides[dependencies.get_assurance_repository] = lambda: assurance_repository
    app.dependency_overrides[dependencies.get_vulnerability_repository] = lambda: vulnerability_repository
    app.dependency_overrides[dependencies.get_experiment_version_repository] = lambda: experiment_version_repository
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
