"""Login/logout business logic (V2 Phase 6, Step 1). Route-layer-agnostic -
zeroshield.api.routes.auth is the only place this is wired to cookies/HTTP.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from zeroshield.audit.models import Action
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role, SessionRecord, User
from zeroshield.auth.passwords import hash_password, verify_password
from zeroshield.auth.repository import AuthRepository

SESSION_TTL = timedelta(hours=12)
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

# A real Argon2id hash of a value nobody could ever supply as a password (a
# random token generated once at import time) - used only as
# verify_password's comparison target for unknown usernames, so hashing cost
# is identical whether or not the username exists. Never itself a valid
# credential for any account.
_DUMMY_HASH = hash_password(f"unused-dummy-{secrets.token_hex(16)}")


class InvalidCredentialsError(Exception):
    """Deliberately identical for 'unknown username' and 'wrong password' -
    never lets a caller distinguish the two, which would let an attacker
    enumerate valid usernames."""


class AccountLockedError(Exception):
    def __init__(self, locked_until: datetime) -> None:
        self.locked_until = locked_until
        super().__init__(f"account is locked until {locked_until.isoformat()}")


class AccountInactiveError(Exception):
    pass


@dataclass(frozen=True)
class LoginResult:
    user: User
    raw_session_token: str
    session: SessionRecord


def _hash_session_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class AuthService:
    def __init__(self, auth_repository: AuthRepository, audit_repository: AuditRepository) -> None:
        self._auth_repository = auth_repository
        self._audit_repository = audit_repository

    def login(
        self, *, username: str, password: str, ip_address: str | None, user_agent: str | None, request_id: str | None
    ) -> LoginResult:
        candidate = self._auth_repository.get_user_by_username(username)

        if candidate is not None and candidate.locked_until is not None and candidate.locked_until > datetime.now(UTC):
            self._audit_repository.record(
                actor_user_id=candidate.user_id, actor_username=candidate.username, actor_role=candidate.role.value,
                action=Action.LOGIN_FAILURE, target_type="user", target_id=candidate.user_id, request_id=request_id,
                metadata={"reason": "account_locked"},
            )
            raise AccountLockedError(candidate.locked_until)

        # Deliberately still runs the (slow, memory-hard) hash comparison even
        # when the username doesn't exist, against a fixed dummy hash - a
        # missing-user short-circuit would let an attacker distinguish
        # "unknown username" from "wrong password" via response timing.
        password_hash = candidate.password_hash if candidate is not None else _DUMMY_HASH
        password_ok = verify_password(password, password_hash)

        if candidate is None or not password_ok:
            if candidate is not None:
                self._record_failed_attempt(candidate.user_id, candidate.failed_login_attempts, request_id)
            else:
                self._audit_repository.record(
                    actor_user_id=None, actor_username=username, actor_role=None, action=Action.LOGIN_FAILURE,
                    target_type="user", target_id=None, request_id=request_id, metadata={"reason": "unknown_username"},
                )
            raise InvalidCredentialsError("invalid username or password")

        if not candidate.active:
            self._audit_repository.record(
                actor_user_id=candidate.user_id, actor_username=candidate.username, actor_role=candidate.role.value,
                action=Action.LOGIN_FAILURE, target_type="user", target_id=candidate.user_id, request_id=request_id,
                metadata={"reason": "account_inactive"},
            )
            raise AccountInactiveError("this account has been deactivated")

        self._auth_repository.record_login_success(candidate.user_id)
        self._auth_repository.delete_expired_sessions()

        raw_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + SESSION_TTL
        session = self._auth_repository.create_session(
            session_id_hash=_hash_session_token(raw_token), user_id=candidate.user_id, expires_at=expires_at,
            ip_address=ip_address, user_agent=user_agent,
        )

        self._audit_repository.record(
            actor_user_id=candidate.user_id, actor_username=candidate.username, actor_role=candidate.role.value,
            action=Action.LOGIN_SUCCESS, target_type="user", target_id=candidate.user_id, request_id=request_id,
            metadata={"ip_address": ip_address} if ip_address else {},
        )

        user = User(
            user_id=candidate.user_id, username=candidate.username, role=candidate.role, active=candidate.active,
            created_at=candidate.created_at, updated_at=candidate.updated_at,
        )
        return LoginResult(user=user, raw_session_token=raw_token, session=session)

    def _record_failed_attempt(self, user_id: str, current_failures: int, request_id: str | None) -> None:
        new_count = current_failures + 1
        lock_until = datetime.now(UTC) + LOCKOUT_DURATION if new_count >= MAX_FAILED_LOGIN_ATTEMPTS else None
        self._auth_repository.record_login_failure(user_id, lock_until=lock_until)
        user = self._auth_repository.get_user(user_id)
        self._audit_repository.record(
            actor_user_id=user_id, actor_username=user.username if user else None,
            actor_role=user.role.value if user else None, action=Action.LOGIN_FAILURE, target_type="user",
            target_id=user_id, request_id=request_id, metadata={"reason": "bad_password", "attempt": new_count},
        )
        if lock_until is not None:
            self._audit_repository.record(
                actor_user_id=user_id, actor_username=user.username if user else None,
                actor_role=user.role.value if user else None, action=Action.ACCOUNT_LOCKED, target_type="user",
                target_id=user_id, request_id=request_id, metadata={"locked_until": lock_until.isoformat()},
            )

    def logout(self, *, raw_session_token: str, actor: User | None, request_id: str | None) -> None:
        self._auth_repository.delete_session(_hash_session_token(raw_session_token))
        if actor is not None:
            self._audit_repository.record(
                actor_user_id=actor.user_id, actor_username=actor.username, actor_role=actor.role.value,
                action=Action.LOGOUT, target_type="user", target_id=actor.user_id, request_id=request_id, metadata={},
            )

    def get_user_for_session(self, raw_session_token: str) -> User | None:
        result = self._auth_repository.get_session_with_user(_hash_session_token(raw_session_token))
        if result is None:
            return None
        session, user = result
        if session.expires_at <= datetime.now(UTC):
            self._auth_repository.delete_session(session.session_id)
            return None
        if not user.active:
            return None
        self._auth_repository.touch_session(session.session_id)
        return user

    def list_users(self) -> list[User]:
        return self._auth_repository.list_users()

    def create_user(
        self, *, username: str, password_hash: str, role: Role, actor: User, request_id: str | None
    ) -> User:
        created = self._auth_repository.create_user(username=username, password_hash=password_hash, role=role)
        self._audit_repository.record(
            actor_user_id=actor.user_id, actor_username=actor.username, actor_role=actor.role.value,
            action=Action.USER_CREATED, target_type="user", target_id=created.user_id, request_id=request_id,
            metadata={"username": created.username, "role": created.role.value},
        )
        return created

    def update_user_role(self, user_id: str, *, role: Role, actor: User, request_id: str | None) -> User | None:
        before = self._auth_repository.get_user(user_id)
        updated = self._auth_repository.update_user(user_id, role=role)
        if updated is None:
            return None
        self._audit_repository.record(
            actor_user_id=actor.user_id, actor_username=actor.username, actor_role=actor.role.value,
            action=Action.USER_ROLE_CHANGED, target_type="user", target_id=user_id, request_id=request_id,
            metadata={}, previous_state={"role": before.role.value} if before else None,
            new_state={"role": updated.role.value},
        )
        return updated

    def set_user_active(self, user_id: str, *, active: bool, actor: User, request_id: str | None) -> User | None:
        updated = self._auth_repository.update_user(user_id, active=active)
        if updated is None:
            return None
        self._audit_repository.record(
            actor_user_id=actor.user_id, actor_username=actor.username, actor_role=actor.role.value,
            action=Action.USER_REACTIVATED if active else Action.USER_DEACTIVATED, target_type="user",
            target_id=user_id, request_id=request_id, metadata={},
        )
        return updated
