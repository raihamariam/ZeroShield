"""Tests NullRunRepository (the default when DATABASE_URL is unset) and
PostgresRunRepository against an in-memory SQLite engine - the implementation
only uses portable SQLAlchemy Core/ORM, so this exercises the real code path
without needing a live Postgres server. Genuine Postgres verification is done
via the opt-in tests/integration/test_worker_postgres_real_db.py, mirroring
the RabbitMQ real-broker precedent (test_api_worker_real_broker.py).
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from zeroshield.db.base import Base
from zeroshield.models.enums import RunEventType
from zeroshield.repositories import NullRunRepository
from zeroshield.repositories.postgres_run_repository import PostgresRunRepository

FIXED_TIME = datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC)


def _fixed_clock() -> datetime:
    return FIXED_TIME


@pytest.fixture
def sql_repo() -> PostgresRunRepository:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return PostgresRunRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


def test_null_run_repository_record_event_returns_event_but_persists_nothing() -> None:
    repo = NullRunRepository()
    event = repo.record_event(
        "JOB-1", "ZC-VPN-EXP-001", RunEventType.QUEUED, clock=_fixed_clock
    )
    assert event.run_id == "JOB-1"
    assert event.event_type == RunEventType.QUEUED
    assert event.occurred_at == FIXED_TIME
    assert repo.list_events("JOB-1") == []


def test_postgres_run_repository_records_and_lists_events_in_order(
    sql_repo: PostgresRunRepository,
) -> None:
    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.QUEUED)
    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.PREPARING)
    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.SAFETY_CHECK)
    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.COMPLETED, detail={"total_cases": 22})

    events = sql_repo.list_events("JOB-1")
    assert [e.event_type for e in events] == [
        RunEventType.QUEUED,
        RunEventType.PREPARING,
        RunEventType.SAFETY_CHECK,
        RunEventType.COMPLETED,
    ]
    assert events[-1].detail == {"total_cases": 22}
    assert all(e.run_id == "JOB-1" and e.experiment_id == "ZC-VPN-EXP-001" for e in events)


def test_postgres_run_repository_isolates_events_by_run_id(sql_repo: PostgresRunRepository) -> None:
    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.QUEUED)
    sql_repo.record_event("JOB-2", "ZC-TELECOM-EXP-001", RunEventType.QUEUED)

    assert len(sql_repo.list_events("JOB-1")) == 1
    assert len(sql_repo.list_events("JOB-2")) == 1
    assert sql_repo.list_events("JOB-1")[0].experiment_id == "ZC-VPN-EXP-001"


def test_postgres_run_repository_list_events_for_unknown_run_is_empty(
    sql_repo: PostgresRunRepository,
) -> None:
    assert sql_repo.list_events("JOB-does-not-exist") == []


def test_postgres_run_repository_upserts_run_current_status(sql_repo: PostgresRunRepository) -> None:
    """The `runs` row tracks the most recent status - record_event must update it,
    not just append a run_events row, so a future "get current run status" query
    reads the latest state without scanning the whole event history."""
    from sqlalchemy import select

    from zeroshield.db.models import RunORM

    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.QUEUED, execution_context="local_unit_test")
    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.COMPLETED)

    with sql_repo._session_factory() as session:
        run = session.execute(select(RunORM).where(RunORM.job_id == "JOB-1")).scalar_one()
        assert run.current_status == RunEventType.COMPLETED.value
        assert run.execution_context == "local_unit_test"


def test_postgres_run_repository_updates_execution_context_on_existing_run(
    sql_repo: PostgresRunRepository,
) -> None:
    """A later record_event() call that passes execution_context must update the
    already-existing run row, not just the newly-created case."""
    from sqlalchemy import select

    from zeroshield.db.models import RunORM

    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.QUEUED, execution_context="local_unit_test")
    sql_repo.record_event("JOB-1", "ZC-VPN-EXP-001", RunEventType.COMPLETED, execution_context="experiment_run")

    with sql_repo._session_factory() as session:
        run = session.execute(select(RunORM).where(RunORM.job_id == "JOB-1")).scalar_one()
        assert run.execution_context == "experiment_run"
