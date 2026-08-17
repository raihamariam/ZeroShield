"""PostgreSQL-backed persistence for audit_events (V2 Phase 6, Step 3).
Append-only: this module deliberately exposes no update/delete method."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zeroshield.audit.models import AuditEvent
from zeroshield.db.models import AuditEventORM


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _from_orm(row: AuditEventORM) -> AuditEvent:
    return AuditEvent(
        audit_id=row.audit_id, occurred_at=_as_utc(row.occurred_at), actor_user_id=row.actor_user_id,
        actor_username=row.actor_username, actor_role=row.actor_role, action=row.action,
        target_type=row.target_type, target_id=row.target_id, request_id=row.request_id,
        metadata=row.metadata_json or {}, previous_state=row.previous_state, new_state=row.new_state,
    )


class AuditRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(
        self,
        *,
        actor_user_id: str | None,
        actor_username: str | None,
        actor_role: str | None,
        action: str,
        target_type: str | None,
        target_id: str | None,
        request_id: str | None,
        metadata: dict[str, Any],
        previous_state: dict[str, Any] | None = None,
        new_state: dict[str, Any] | None = None,
    ) -> AuditEvent:
        with self._session_factory() as session:
            row = AuditEventORM(
                audit_id=f"AUDIT-{uuid.uuid4().hex}", occurred_at=datetime.now(UTC),
                actor_user_id=actor_user_id, actor_username=actor_username, actor_role=actor_role,
                action=action, target_type=target_type, target_id=target_id, request_id=request_id,
                metadata_json=metadata, previous_state=previous_state, new_state=new_state,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _from_orm(row)

    def list_events(
        self,
        *,
        action: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        actor_user_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AuditEvent], int]:
        with self._session_factory() as session:
            query = select(AuditEventORM)
            if action is not None:
                query = query.where(AuditEventORM.action == action)
            if target_type is not None:
                query = query.where(AuditEventORM.target_type == target_type)
            if target_id is not None:
                query = query.where(AuditEventORM.target_id == target_id)
            if actor_user_id is not None:
                query = query.where(AuditEventORM.actor_user_id == actor_user_id)

            total = len(session.execute(query).scalars().all())
            rows = (
                session.execute(query.order_by(AuditEventORM.occurred_at.desc()).offset(offset).limit(limit))
                .scalars()
                .all()
            )
            return [_from_orm(r) for r in rows], total
