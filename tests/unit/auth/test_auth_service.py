"""Tests the security-critical behaviour of zeroshield.auth.service.AuthService:
username-enumeration resistance, lockout after repeated failures, session
issuance/expiry, and that every login attempt (success or failure) produces
an audit event (V2 Phase 6, Steps 1/3)."""

from datetime import UTC, datetime, timedelta

import pytest

from zeroshield.audit.models import Action
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role
from zeroshield.auth.passwords import hash_password
from zeroshield.auth.repository import AuthRepository
from zeroshield.auth.service import (
    MAX_FAILED_LOGIN_ATTEMPTS,
    AccountInactiveError,
    AccountLockedError,
    AuthService,
    InvalidCredentialsError,
)


@pytest.fixture
def service(auth_repo: AuthRepository, audit_repo: AuditRepository) -> AuthService:
    return AuthService(auth_repo, audit_repo)


def _seed_user(auth_repo: AuthRepository, *, username: str = "alice", password: str = "correct-horse-battery", role: Role = Role.RESEARCHER):
    return auth_repo.create_user(username=username, password_hash=hash_password(password), role=role)


def test_login_success_creates_a_session_and_audits(
    service: AuthService, auth_repo: AuthRepository, audit_repo: AuditRepository
) -> None:
    _seed_user(auth_repo)
    result = service.login(username="alice", password="correct-horse-battery", ip_address="127.0.0.1", user_agent="pytest", request_id="req-1")
    assert result.user.username == "alice"
    assert len(result.raw_session_token) > 20

    events, _total = audit_repo.list_events(action=Action.LOGIN_SUCCESS)
    assert len(events) == 1
    assert events[0].actor_username == "alice"
    assert events[0].request_id == "req-1"


def test_login_wrong_password_raises_invalid_credentials_and_audits(
    service: AuthService, auth_repo: AuthRepository, audit_repo: AuditRepository
) -> None:
    _seed_user(auth_repo)
    with pytest.raises(InvalidCredentialsError):
        service.login(username="alice", password="wrong", ip_address=None, user_agent=None, request_id=None)

    events, _total = audit_repo.list_events(action=Action.LOGIN_FAILURE)
    assert len(events) == 1


def test_login_unknown_username_raises_the_same_error_as_wrong_password(
    service: AuthService, auth_repo: AuthRepository
) -> None:
    """Username-enumeration resistance: both cases must be indistinguishable
    to the caller (Step 1's "modern secure ... practices")."""
    _seed_user(auth_repo)
    with pytest.raises(InvalidCredentialsError) as wrong_password_exc:
        service.login(username="alice", password="wrong", ip_address=None, user_agent=None, request_id=None)
    with pytest.raises(InvalidCredentialsError) as unknown_user_exc:
        service.login(username="nobody", password="whatever", ip_address=None, user_agent=None, request_id=None)
    assert str(wrong_password_exc.value) == str(unknown_user_exc.value)


def test_repeated_failures_lock_the_account(service: AuthService, auth_repo: AuthRepository, audit_repo: AuditRepository) -> None:
    _seed_user(auth_repo)
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 1):
        with pytest.raises(InvalidCredentialsError):
            service.login(username="alice", password="wrong", ip_address=None, user_agent=None, request_id=None)

    # The Nth failure locks the account...
    with pytest.raises(InvalidCredentialsError):
        service.login(username="alice", password="wrong", ip_address=None, user_agent=None, request_id=None)

    # ...and every subsequent attempt is rejected as locked, even with the correct password.
    with pytest.raises(AccountLockedError):
        service.login(username="alice", password="correct-horse-battery", ip_address=None, user_agent=None, request_id=None)

    lock_events, _total = audit_repo.list_events(action=Action.ACCOUNT_LOCKED)
    assert len(lock_events) == 1


def test_successful_login_resets_failure_count(service: AuthService, auth_repo: AuthRepository) -> None:
    _seed_user(auth_repo)
    with pytest.raises(InvalidCredentialsError):
        service.login(username="alice", password="wrong", ip_address=None, user_agent=None, request_id=None)
    service.login(username="alice", password="correct-horse-battery", ip_address=None, user_agent=None, request_id=None)

    fetched = auth_repo.get_user_by_username("alice")
    assert fetched is not None
    assert fetched.failed_login_attempts == 0


def test_login_rejects_inactive_account(service: AuthService, auth_repo: AuthRepository) -> None:
    user = _seed_user(auth_repo)
    auth_repo.update_user(user.user_id, active=False)
    with pytest.raises(AccountInactiveError):
        service.login(username="alice", password="correct-horse-battery", ip_address=None, user_agent=None, request_id=None)


def test_get_user_for_session_returns_none_for_unknown_token(service: AuthService, auth_repo: AuthRepository) -> None:
    assert service.get_user_for_session("not-a-real-token") is None


def test_get_user_for_session_returns_none_for_expired_session(
    service: AuthService, auth_repo: AuthRepository
) -> None:
    _seed_user(auth_repo)
    result = service.login(username="alice", password="correct-horse-battery", ip_address=None, user_agent=None, request_id=None)
    # Simulate expiry by directly rewriting the session's expires_at in the past.
    import hashlib

    session_hash = hashlib.sha256(result.raw_session_token.encode("utf-8")).hexdigest()
    with auth_repo._session_factory() as session:
        from zeroshield.db.models import SessionORM

        row = session.get(SessionORM, session_hash)
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    assert service.get_user_for_session(result.raw_session_token) is None


def test_logout_deletes_the_session(service: AuthService, auth_repo: AuthRepository) -> None:
    _seed_user(auth_repo)
    result = service.login(username="alice", password="correct-horse-battery", ip_address=None, user_agent=None, request_id=None)
    assert service.get_user_for_session(result.raw_session_token) is not None
    service.logout(raw_session_token=result.raw_session_token, actor=result.user, request_id=None)
    assert service.get_user_for_session(result.raw_session_token) is None


def test_create_user_and_role_change_are_audited(
    service: AuthService, auth_repo: AuthRepository, audit_repo: AuditRepository
) -> None:
    admin = _seed_user(auth_repo, username="admin", role=Role.ADMIN)
    created = service.create_user(username="newuser", password_hash=hash_password("whatever-secure-1"), role=Role.VIEWER, actor=admin, request_id="req-2")
    assert created.role == Role.VIEWER

    updated = service.update_user_role(created.user_id, role=Role.REVIEWER, actor=admin, request_id="req-3")
    assert updated is not None
    assert updated.role == Role.REVIEWER

    created_events, _ = audit_repo.list_events(action=Action.USER_CREATED)
    role_events, _ = audit_repo.list_events(action=Action.USER_ROLE_CHANGED)
    assert len(created_events) == 1
    assert len(role_events) == 1
    assert role_events[0].previous_state == {"role": "viewer"}
    assert role_events[0].new_state == {"role": "reviewer"}
