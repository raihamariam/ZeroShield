import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.audit.repository import AuditRepository
from zeroshield.db.base import Base


@pytest.fixture
def audit_repo() -> AuditRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AuditRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


def test_record_and_list(audit_repo: AuditRepository) -> None:
    event = audit_repo.record(
        actor_user_id="USER-1", actor_username="alice", actor_role="admin", action="user.created",
        target_type="user", target_id="USER-2", request_id="req-1", metadata={"note": "test"},
    )
    assert event.audit_id.startswith("AUDIT-")

    events, total = audit_repo.list_events()
    assert total == 1
    assert events[0].audit_id == event.audit_id
    assert events[0].metadata == {"note": "test"}


def test_list_filters_by_action_target_and_actor(audit_repo: AuditRepository) -> None:
    audit_repo.record(
        actor_user_id="USER-1", actor_username="alice", actor_role="admin", action="user.created",
        target_type="user", target_id="USER-2", request_id=None, metadata={},
    )
    audit_repo.record(
        actor_user_id="USER-1", actor_username="alice", actor_role="admin", action="auth.login_success",
        target_type="user", target_id="USER-1", request_id=None, metadata={},
    )

    by_action, total_by_action = audit_repo.list_events(action="user.created")
    assert total_by_action == 1
    assert by_action[0].action == "user.created"

    by_target, total_by_target = audit_repo.list_events(target_id="USER-1")
    assert total_by_target == 1
    assert by_target[0].action == "auth.login_success"

    _by_actor, total_by_actor = audit_repo.list_events(actor_user_id="USER-1")
    assert total_by_actor == 2


def test_list_is_ordered_most_recent_first(audit_repo: AuditRepository) -> None:
    first = audit_repo.record(
        actor_user_id=None, actor_username=None, actor_role=None, action="a", target_type=None,
        target_id=None, request_id=None, metadata={},
    )
    second = audit_repo.record(
        actor_user_id=None, actor_username=None, actor_role=None, action="b", target_type=None,
        target_id=None, request_id=None, metadata={},
    )
    events, _total = audit_repo.list_events()
    assert [e.audit_id for e in events][:2] == [second.audit_id, first.audit_id] or events[0].action == "b"


def test_previous_and_new_state_round_trip(audit_repo: AuditRepository) -> None:
    audit_repo.record(
        actor_user_id=None, actor_username=None, actor_role=None, action="user.role_changed",
        target_type="user", target_id="USER-1", request_id=None, metadata={},
        previous_state={"role": "viewer"}, new_state={"role": "admin"},
    )
    events, _total = audit_repo.list_events(action="user.role_changed")
    assert events[0].previous_state == {"role": "viewer"}
    assert events[0].new_state == {"role": "admin"}
