from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role, User
from zeroshield.db.base import Base
from zeroshield.services.job_store import RunJobMessage

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
VPN_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-VPN-EXP-001.json"
TELECOM_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-TELECOM-EXP-001.json"


def fake_user(role: Role = Role.ADMIN, *, username: str = "test-admin", user_id: str = "USER-test-admin") -> User:
    """V2 Phase 6: every route now requires an authenticated session. Tests
    that are not themselves testing auth/RBAC use this to override
    get_current_user directly (bypassing real login/sessions/Postgres) with
    a fixed ADMIN identity by default - ADMIN can reach every route, so this
    never masks a real RBAC bug in a test that isn't looking for one.
    Tests that DO test RBAC (see test_auth_routes.py, and the self-approval
    tests in test_studio.py) override this per-test with a narrower role."""
    now = datetime.now(UTC)
    return User(user_id=user_id, username=username, role=role, active=True, created_at=now, updated_at=now)


@pytest.fixture
def results_root(tmp_path: Path) -> Path:
    return tmp_path / "results"


@pytest.fixture
def jobs_dir(tmp_path: Path) -> Path:
    return tmp_path / "jobs"


@pytest.fixture
def published_messages() -> list[RunJobMessage]:
    """Records what submit_run() would have published to RabbitMQ."""
    return []


@pytest.fixture
def audit_repository() -> AuditRepository:
    """In-memory SQLite-backed AuditRepository - every mutating route now
    writes an audit event (V2 Phase 6), so a real (if throwaway) repository
    must be available even in tests that aren't themselves about auditing."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AuditRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def client(
    results_root: Path, jobs_dir: Path, published_messages: list[RunJobMessage], audit_repository: AuditRepository
) -> Iterator[TestClient]:
    """A TestClient with isolated, temporary results/jobs directories and a fake publisher.

    The real experiments/ directory is used as-is (so VPN/Telecom experiments are
    genuinely discoverable), but every run/results/evidence/job call writes to and
    reads from results_root/jobs_dir (tmp_path-based), never the project's real
    directories. get_publisher is overridden with a fake that just records the
    message into published_messages instead of requiring a live RabbitMQ broker -
    genuine end-to-end message-queue delivery is verified manually against a real
    broker (see the Milestone 21 report), not as part of this automated suite, so
    that `pytest` never depends on external infrastructure being up.
    raise_server_exceptions=False makes this client behave like a real HTTP client:
    it returns the response my exception handlers built instead of re-raising for
    debugger convenience (Starlette TestClient's default).
    """
    app.dependency_overrides[dependencies.get_results_root] = lambda: results_root
    app.dependency_overrides[dependencies.get_jobs_dir] = lambda: jobs_dir
    app.dependency_overrides[dependencies.get_publisher] = lambda: published_messages.append
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    app.dependency_overrides[dependencies.get_audit_repository] = lambda: audit_repository
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
