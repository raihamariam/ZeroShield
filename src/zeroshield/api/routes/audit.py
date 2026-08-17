"""Audit trail browsing (V2 Phase 6, Step 3). Read-only - nothing in this
API ever updates or deletes an audit event; zeroshield.audit.repository
exposes no such method to even call by mistake."""

from typing import Annotated

from fastapi import APIRouter, Depends

from zeroshield.api.dependencies import get_audit_repository, require_role
from zeroshield.api.schemas import AuditEventListResponse, AuditEventResponse
from zeroshield.audit.models import AuditEvent
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role, User

router = APIRouter(tags=["audit"])


def _response(event: AuditEvent) -> AuditEventResponse:
    return AuditEventResponse(
        audit_id=event.audit_id, occurred_at=event.occurred_at.isoformat(), actor_user_id=event.actor_user_id,
        actor_username=event.actor_username, actor_role=event.actor_role, action=event.action,
        target_type=event.target_type, target_id=event.target_id, request_id=event.request_id,
        metadata=event.metadata, previous_state=event.previous_state, new_state=event.new_state,
    )


@router.get("/audit-events", response_model=AuditEventListResponse, summary="Browse the audit trail (ADMIN only)")
def list_audit_events(
    repository: Annotated[AuditRepository, Depends(get_audit_repository)],
    _actor: Annotated[User, Depends(require_role(Role.ADMIN))],
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    actor_user_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> AuditEventListResponse:
    events, total = repository.list_events(
        action=action, target_type=target_type, target_id=target_id, actor_user_id=actor_user_id,
        limit=limit, offset=offset,
    )
    return AuditEventListResponse(events=[_response(e) for e in events], total=total, limit=limit, offset=offset)
