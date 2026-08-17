"""PostgreSQL-backed persistence for auth (V2 Phase 6, Step 1). Works against
any SQLAlchemy-supported engine (Postgres in production, in-memory SQLite in
tests), mirroring zeroshield.assurance.repository.AssuranceRepository.
"""

import uuid
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from zeroshield.auth.models import Role, SessionRecord, User, UserWithCredentials
from zeroshield.db.models import SessionORM, UserORM


def _as_utc(value: datetime) -> datetime:
    """SQLite (used in tests) does not round-trip tzinfo on
    DateTime(timezone=True) columns - mirrors the same helper in
    zeroshield.assurance.repository / zeroshield.intelligence.repository."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _as_utc_optional(value: datetime | None) -> datetime | None:
    return None if value is None else _as_utc(value)


def _user_from_orm(row: UserORM) -> User:
    return User(
        user_id=row.user_id, username=row.username, role=Role(row.role), active=row.active,
        created_at=_as_utc(row.created_at), updated_at=_as_utc(row.updated_at),
    )


def _user_with_credentials_from_orm(row: UserORM) -> UserWithCredentials:
    return UserWithCredentials(
        user_id=row.user_id, username=row.username, role=Role(row.role), active=row.active,
        created_at=_as_utc(row.created_at), updated_at=_as_utc(row.updated_at),
        password_hash=row.password_hash, failed_login_attempts=row.failed_login_attempts,
        locked_until=_as_utc_optional(row.locked_until),
    )


def _session_from_orm(row: SessionORM) -> SessionRecord:
    return SessionRecord(
        session_id=row.session_id, user_id=row.user_id, created_at=_as_utc(row.created_at),
        expires_at=_as_utc(row.expires_at), last_used_at=_as_utc(row.last_used_at),
        ip_address=row.ip_address, user_agent=row.user_agent,
    )


class UsernameAlreadyExistsError(Exception):
    pass


class AuthRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Users --------------------------------------------------------------

    def create_user(self, *, username: str, password_hash: str, role: Role) -> User:
        now = datetime.now(UTC)
        with self._session_factory() as session:
            existing = session.execute(select(UserORM).where(UserORM.username == username)).scalar_one_or_none()
            if existing is not None:
                raise UsernameAlreadyExistsError(f"username '{username}' is already registered")
            row = UserORM(
                user_id=f"USER-{uuid.uuid4().hex}", username=username, password_hash=password_hash,
                role=role.value, active=True, failed_login_attempts=0, locked_until=None,
                created_at=now, updated_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _user_from_orm(row)

    def get_user_by_username(self, username: str) -> UserWithCredentials | None:
        with self._session_factory() as session:
            row = session.execute(select(UserORM).where(UserORM.username == username)).scalar_one_or_none()
            return _user_with_credentials_from_orm(row) if row is not None else None

    def get_user(self, user_id: str) -> User | None:
        with self._session_factory() as session:
            row = session.get(UserORM, user_id)
            return _user_from_orm(row) if row is not None else None

    def list_users(self) -> list[User]:
        with self._session_factory() as session:
            rows = session.execute(select(UserORM).order_by(UserORM.username)).scalars().all()
            return [_user_from_orm(r) for r in rows]

    def update_user(self, user_id: str, *, role: Role | None = None, active: bool | None = None) -> User | None:
        with self._session_factory() as session:
            row = session.get(UserORM, user_id)
            if row is None:
                return None
            if role is not None:
                row.role = role.value
            if active is not None:
                row.active = active
            row.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(row)
            return _user_from_orm(row)

    def record_login_success(self, user_id: str) -> None:
        with self._session_factory() as session:
            row = session.get(UserORM, user_id)
            if row is None:
                return
            row.failed_login_attempts = 0
            row.locked_until = None
            row.updated_at = datetime.now(UTC)
            session.commit()

    def record_login_failure(self, user_id: str, *, lock_until: datetime | None) -> None:
        with self._session_factory() as session:
            row = session.get(UserORM, user_id)
            if row is None:
                return
            row.failed_login_attempts += 1
            if lock_until is not None:
                row.locked_until = lock_until
            row.updated_at = datetime.now(UTC)
            session.commit()

    # -- Sessions -------------------------------------------------------------

    def create_session(
        self,
        *,
        session_id_hash: str,
        user_id: str,
        expires_at: datetime,
        ip_address: str | None,
        user_agent: str | None,
    ) -> SessionRecord:
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = SessionORM(
                session_id=session_id_hash, user_id=user_id, created_at=now, expires_at=expires_at,
                last_used_at=now, ip_address=ip_address, user_agent=user_agent,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _session_from_orm(row)

    def get_session_with_user(self, session_id_hash: str) -> tuple[SessionRecord, User] | None:
        with self._session_factory() as session:
            row = session.get(SessionORM, session_id_hash)
            if row is None:
                return None
            user_row = session.get(UserORM, row.user_id)
            if user_row is None:
                return None
            return _session_from_orm(row), _user_from_orm(user_row)

    def touch_session(self, session_id_hash: str) -> None:
        with self._session_factory() as session:
            row = session.get(SessionORM, session_id_hash)
            if row is None:
                return
            row.last_used_at = datetime.now(UTC)
            session.commit()

    def delete_session(self, session_id_hash: str) -> None:
        with self._session_factory() as session:
            session.execute(delete(SessionORM).where(SessionORM.session_id == session_id_hash))
            session.commit()

    def delete_expired_sessions(self, *, now: datetime | None = None) -> int:
        """Best-effort housekeeping (called opportunistically from the login
        route) - an expired-but-undeleted row is already rejected by
        get_session_with_user's expiry check, so this is cleanup, not a
        security boundary."""
        cutoff = now or datetime.now(UTC)
        with self._session_factory() as session:
            # session.execute() is typed to return the generic Result[Any] in
            # SQLAlchemy's stubs, but a Delete construct always returns a
            # CursorResult (which has .rowcount) at runtime - cast rather than
            # `# type: ignore`, since the attribute genuinely exists.
            result = cast(
                CursorResult[Any], session.execute(delete(SessionORM).where(SessionORM.expires_at < cutoff))
            )
            session.commit()
            return result.rowcount or 0
