"""Authentication hardening (V2 Phase 6, Step 4): auth bypass attempts,
SQL-injection-shaped credentials, session tampering, and secret leakage.
Extends (never weakens) the existing security suite - see
tests/unit/auth/test_auth_service.py for the lockout/enumeration-resistance
unit tests this complements at the HTTP layer.
"""

from fastapi.testclient import TestClient

from zeroshield.auth.models import Role
from zeroshield.auth.passwords import hash_password
from zeroshield.auth.repository import AuthRepository

SQLI_PAYLOADS = [
    "admin' OR '1'='1",
    "admin'--",
    "'; DROP TABLE users; --",
    "admin' OR 1=1--",
    "\" OR \"\"=\"",
]


def _seed_admin(auth_repository: AuthRepository) -> None:
    auth_repository.create_user(username="admin", password_hash=hash_password("correct-horse-battery-1"), role=Role.ADMIN)


# -- Auth bypass: no route works without a real session ------------------------


def test_protected_routes_reject_requests_with_no_cookie_at_all(client: TestClient) -> None:
    """The fixture's `client` pre-authenticates via dependency override, which
    is a test convenience, not a real cookie - a genuinely cookie-less
    httpx.Client (bypassing the override) must still be rejected by every
    protected route. Simulated here by clearing the override and issuing a
    bare request."""
    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    try:
        response = client.get("/controls")
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "not_authenticated"
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved


def test_forged_session_cookie_is_rejected(client: TestClient) -> None:
    """A session_id is the SHA-256 hash of a random 32-byte token - an
    attacker guessing or forging a cookie value has no path to a valid hash
    without already knowing a real session's raw token. Popping the
    get_current_user override lets the *real* dependency chain run
    (get_auth_service -> get_auth_repository/get_audit_repository, both
    still pointed at this test's in-memory repos by the client fixture), so
    this exercises the actual lookup-and-reject logic, not a stub."""
    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    try:
        response = client.get("/controls", cookies={"zeroshield_session": "totally-forged-token-value"})
        assert response.status_code == 401
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved


def test_expired_session_is_rejected_not_treated_as_valid(client: TestClient, auth_repository: AuthRepository) -> None:
    """A logout (or expiry) must actually deny the very next request with
    that cookie - never a stale "still valid" state. Creates a real,
    already-expired session directly in the repository (bypassing login's
    SESSION_TTL) to prove expiry is enforced on lookup, not just at issue
    time."""
    import hashlib
    from datetime import UTC, datetime, timedelta

    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    user = auth_repository.create_user(username="dave", password_hash=hash_password("whatever-secure-1"), role=Role.VIEWER)
    raw_token = "a-raw-token-for-this-test-only"
    session_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    auth_repository.create_session(
        session_id_hash=session_hash, user_id=user.user_id,
        expires_at=datetime.now(UTC) - timedelta(seconds=1), ip_address=None, user_agent=None,
    )

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    try:
        response = client.get("/controls", cookies={"zeroshield_session": raw_token})
        assert response.status_code == 401
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved


# -- SQL-injection-shaped credentials -------------------------------------------


def test_login_with_sql_injection_shaped_username_is_ordinary_invalid_credentials(
    client: TestClient, auth_repository: AuthRepository
) -> None:
    """SQLAlchemy's ORM always parameterises queries - a SQL-metacharacter
    username must behave exactly like any other unknown username (401,
    generic message), never a 500, never a bypass, never a different error
    shape that would reveal a query was malformed."""
    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    _seed_admin(auth_repository)
    try:
        for payload in SQLI_PAYLOADS:
            response = client.post("/auth/login", json={"username": payload, "password": "whatever"})
            assert response.status_code == 401, f"payload {payload!r} did not cleanly 401"
            assert response.json()["detail"]["error"] == "invalid_credentials"
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved


def test_login_with_sql_injection_shaped_password_does_not_bypass_auth(
    client: TestClient, auth_repository: AuthRepository
) -> None:
    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    _seed_admin(auth_repository)
    try:
        for payload in SQLI_PAYLOADS:
            response = client.post("/auth/login", json={"username": "admin", "password": payload})
            assert response.status_code == 401
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved


# -- Secret leakage --------------------------------------------------------------


def test_login_response_body_never_contains_the_session_token(client: TestClient, auth_repository: AuthRepository) -> None:
    """The raw session token must only ever appear in the Set-Cookie header -
    never echoed into the JSON body, which a browser extension, proxy log,
    or error-reporting tool could capture."""
    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    _seed_admin(auth_repository)
    try:
        response = client.post("/auth/login", json={"username": "admin", "password": "correct-horse-battery-1"})
        assert response.status_code == 200
        raw_token = response.cookies.get("zeroshield_session")
        assert raw_token is not None
        assert raw_token not in response.text
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved


def test_login_response_never_contains_the_password_hash(client: TestClient, auth_repository: AuthRepository) -> None:
    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    user = auth_repository.create_user(username="carol", password_hash=hash_password("some-real-password-1"), role=Role.VIEWER)
    try:
        response = client.post("/auth/login", json={"username": "carol", "password": "some-real-password-1"})
        assert "$argon2id$" not in response.text
        assert "password" not in response.json()["user"]
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved
    assert user.username == "carol"


def test_login_failure_audit_events_never_contain_the_attempted_password(
    client: TestClient, auth_repository: AuthRepository, audit_repository
) -> None:
    """metadata on a LOGIN_FAILURE event records *that* a password was
    wrong, never the value itself - see zeroshield.auth.service."""
    from zeroshield.api import dependencies
    from zeroshield.api.app import app

    saved = app.dependency_overrides.pop(dependencies.get_current_user, None)
    _seed_admin(auth_repository)
    secret_attempted_password = "unique-marker-x9f2q7-should-not-leak"
    try:
        client.post("/auth/login", json={"username": "admin", "password": secret_attempted_password})
    finally:
        if saved is not None:
            app.dependency_overrides[dependencies.get_current_user] = saved

    events, _total = audit_repository.list_events(action="auth.login_failure")
    assert len(events) >= 1
    for event in events:
        assert secret_attempted_password not in str(event.metadata)
