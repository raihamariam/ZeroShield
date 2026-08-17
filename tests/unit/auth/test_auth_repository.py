from datetime import UTC, datetime, timedelta

import pytest

from zeroshield.auth.models import Role
from zeroshield.auth.repository import AuthRepository, UsernameAlreadyExistsError


def test_create_and_get_user_by_username(auth_repo: AuthRepository) -> None:
    created = auth_repo.create_user(username="alice", password_hash="hash", role=Role.RESEARCHER)
    fetched = auth_repo.get_user_by_username("alice")
    assert fetched is not None
    assert fetched.user_id == created.user_id
    assert fetched.role == Role.RESEARCHER
    assert fetched.password_hash == "hash"


def test_create_user_rejects_duplicate_username(auth_repo: AuthRepository) -> None:
    auth_repo.create_user(username="alice", password_hash="h1", role=Role.VIEWER)
    with pytest.raises(UsernameAlreadyExistsError):
        auth_repo.create_user(username="alice", password_hash="h2", role=Role.ADMIN)


def test_get_user_by_username_unknown_is_none(auth_repo: AuthRepository) -> None:
    assert auth_repo.get_user_by_username("nobody") is None


def test_update_user_role_and_active(auth_repo: AuthRepository) -> None:
    created = auth_repo.create_user(username="bob", password_hash="h", role=Role.VIEWER)
    updated = auth_repo.update_user(created.user_id, role=Role.ADMIN, active=False)
    assert updated is not None
    assert updated.role == Role.ADMIN
    assert updated.active is False


def test_update_unknown_user_returns_none(auth_repo: AuthRepository) -> None:
    assert auth_repo.update_user("USER-does-not-exist", role=Role.ADMIN) is None


def test_login_failure_tracking_and_lockout(auth_repo: AuthRepository) -> None:
    created = auth_repo.create_user(username="carol", password_hash="h", role=Role.RESEARCHER)
    lock_until = datetime.now(UTC) + timedelta(minutes=15)
    auth_repo.record_login_failure(created.user_id, lock_until=None)
    auth_repo.record_login_failure(created.user_id, lock_until=lock_until)
    fetched = auth_repo.get_user_by_username("carol")
    assert fetched is not None
    assert fetched.failed_login_attempts == 2
    assert fetched.locked_until == lock_until

    auth_repo.record_login_success(created.user_id)
    fetched_again = auth_repo.get_user_by_username("carol")
    assert fetched_again is not None
    assert fetched_again.failed_login_attempts == 0
    assert fetched_again.locked_until is None


def test_session_create_get_touch_and_delete(auth_repo: AuthRepository) -> None:
    user = auth_repo.create_user(username="dave", password_hash="h", role=Role.VIEWER)
    expires_at = datetime.now(UTC) + timedelta(hours=1)
    session = auth_repo.create_session(
        session_id_hash="hash123", user_id=user.user_id, expires_at=expires_at, ip_address="127.0.0.1",
        user_agent="pytest",
    )
    result = auth_repo.get_session_with_user("hash123")
    assert result is not None
    fetched_session, fetched_user = result
    assert fetched_session.session_id == session.session_id
    assert fetched_user.user_id == user.user_id

    auth_repo.touch_session("hash123")
    auth_repo.delete_session("hash123")
    assert auth_repo.get_session_with_user("hash123") is None


def test_delete_expired_sessions(auth_repo: AuthRepository) -> None:
    user = auth_repo.create_user(username="erin", password_hash="h", role=Role.VIEWER)
    past = datetime.now(UTC) - timedelta(hours=1)
    future = datetime.now(UTC) + timedelta(hours=1)
    auth_repo.create_session(session_id_hash="expired", user_id=user.user_id, expires_at=past, ip_address=None, user_agent=None)
    auth_repo.create_session(session_id_hash="valid", user_id=user.user_id, expires_at=future, ip_address=None, user_agent=None)

    deleted = auth_repo.delete_expired_sessions()
    assert deleted == 1
    assert auth_repo.get_session_with_user("expired") is None
    assert auth_repo.get_session_with_user("valid") is not None
