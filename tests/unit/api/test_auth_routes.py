"""Tests /auth/* and /users/* (V2 Phase 6, Steps 1-2) against a real
in-memory-SQLite-backed AuthRepository/AuditRepository - no live Postgres.
Covers login/logout/me, the session cookie itself, RBAC enforcement (a
VIEWER cannot reach an ADMIN-only route), and that /auth/login is the only
route reachable without a session."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role
from zeroshield.auth.passwords import hash_password
from zeroshield.auth.repository import AuthRepository
from zeroshield.db.base import Base


@pytest.fixture
def repos() -> tuple[AuthRepository, AuditRepository]:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return AuthRepository(factory), AuditRepository(factory)


@pytest.fixture
def client(repos: tuple[AuthRepository, AuditRepository]) -> Iterator[TestClient]:
    auth_repo, audit_repo = repos
    app.dependency_overrides[dependencies.get_auth_repository] = lambda: auth_repo
    app.dependency_overrides[dependencies.get_audit_repository] = lambda: audit_repo
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _seed(auth_repo: AuthRepository, *, username: str, password: str, role: Role):
    return auth_repo.create_user(username=username, password_hash=hash_password(password), role=role)


def test_login_sets_httponly_session_cookie(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="alice", password="correct-horse-battery", role=Role.RESEARCHER)

    response = client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "alice"
    assert "zeroshield_session" in response.cookies


def test_login_wrong_password_is_401(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="alice", password="correct-horse-battery", role=Role.RESEARCHER)
    response = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "invalid_credentials"


def test_me_without_a_session_is_401(client: TestClient) -> None:
    response = client.get("/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "not_authenticated"


def test_me_with_a_session_returns_the_user(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="alice", password="correct-horse-battery", role=Role.RESEARCHER)
    client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})

    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "alice"
    assert response.json()["role"] == "researcher"


def test_logout_invalidates_the_session(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="alice", password="correct-horse-battery", role=Role.RESEARCHER)
    client.post("/auth/login", json={"username": "alice", "password": "correct-horse-battery"})
    assert client.get("/auth/me").status_code == 200

    logout_response = client.post("/auth/logout")
    assert logout_response.status_code == 204
    assert client.get("/auth/me").status_code == 401


def test_viewer_cannot_reach_admin_only_users_route(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="viewer1", password="correct-horse-battery", role=Role.VIEWER)
    client.post("/auth/login", json={"username": "viewer1", "password": "correct-horse-battery"})

    response = client.get("/users")
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "forbidden"


def test_admin_can_create_and_list_users(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="admin1", password="correct-horse-battery", role=Role.ADMIN)
    client.post("/auth/login", json={"username": "admin1", "password": "correct-horse-battery"})

    created = client.post("/users", json={"username": "newresearcher", "password": "another-secure-pw", "role": "researcher"})
    assert created.status_code == 201
    assert created.json()["role"] == "researcher"

    listed = client.get("/users")
    assert listed.status_code == 200
    usernames = {u["username"] for u in listed.json()["users"]}
    assert {"admin1", "newresearcher"} <= usernames


def test_admin_create_user_rejects_short_password(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="admin1", password="correct-horse-battery", role=Role.ADMIN)
    client.post("/auth/login", json={"username": "admin1", "password": "correct-horse-battery"})

    response = client.post("/users", json={"username": "shortpw", "password": "tooshort", "role": "viewer"})
    assert response.status_code == 422


def test_admin_can_change_a_users_role(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="admin1", password="correct-horse-battery", role=Role.ADMIN)
    other = _seed(auth_repo, username="bob", password="correct-horse-battery", role=Role.VIEWER)
    client.post("/auth/login", json={"username": "admin1", "password": "correct-horse-battery"})

    response = client.patch(f"/users/{other.user_id}/role", json={"role": "reviewer"})
    assert response.status_code == 200
    assert response.json()["role"] == "reviewer"


def test_admin_can_deactivate_a_user(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="admin1", password="correct-horse-battery", role=Role.ADMIN)
    other = _seed(auth_repo, username="bob", password="correct-horse-battery", role=Role.VIEWER)
    client.post("/auth/login", json={"username": "admin1", "password": "correct-horse-battery"})

    response = client.patch(f"/users/{other.user_id}/active", json={"active": False})
    assert response.status_code == 200
    assert response.json()["active"] is False


def test_audit_events_route_requires_admin(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="researcher1", password="correct-horse-battery", role=Role.RESEARCHER)
    client.post("/auth/login", json={"username": "researcher1", "password": "correct-horse-battery"})

    response = client.get("/audit-events")
    assert response.status_code == 403


def test_admin_can_browse_audit_events(client: TestClient, repos) -> None:
    auth_repo, _ = repos
    _seed(auth_repo, username="admin1", password="correct-horse-battery", role=Role.ADMIN)
    client.post("/auth/login", json={"username": "admin1", "password": "correct-horse-battery"})

    response = client.get("/audit-events")
    assert response.status_code == 200
    body = response.json()
    # The login itself is already an audited event.
    assert body["total"] >= 1
    assert any(e["action"] == "auth.login_success" for e in body["events"])
