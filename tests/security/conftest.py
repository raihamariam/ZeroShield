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
from zeroshield.db.base import Base
from zeroshield.services.job_store import RunJobMessage


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
def audit_repository() -> AuditRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AuditRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def client(
    results_root: Path, jobs_dir: Path, published_messages: list[RunJobMessage], audit_repository: AuditRepository
) -> Iterator[TestClient]:
    """Same wiring as tests/unit/api/conftest.py's client fixture: the real
    experiments/ directory, isolated tmp_path results/jobs directories, and a
    fake publisher so no live RabbitMQ broker is required. Also authenticated
    as a fixed ADMIN (V2 Phase 6) - this suite is about path-traversal/
    injection/malformed-input hardening at the route-parameter level, not
    about auth/RBAC itself (auth/RBAC gets its own dedicated security tests),
    so every request here is pre-authenticated to reach the actual handler
    under test."""
    app.dependency_overrides[dependencies.get_results_root] = lambda: results_root
    app.dependency_overrides[dependencies.get_jobs_dir] = lambda: jobs_dir
    app.dependency_overrides[dependencies.get_publisher] = lambda: published_messages.append
    app.dependency_overrides[dependencies.get_audit_repository] = lambda: audit_repository
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
