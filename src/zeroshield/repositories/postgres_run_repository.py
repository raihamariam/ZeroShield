"""SQL-backed RunRepository - PostgreSQL in production (see docker-compose.yml's
`postgres` service and zeroshield.db.session's DATABASE_URL default), any
SQLAlchemy-supported engine (e.g. in-memory SQLite) in unit tests, since the
implementation only uses portable SQLAlchemy Core/ORM, never a Postgres-only
dialect feature. Requires the optional "db" extra - see
zeroshield.repositories.run_repository's module docstring for why this class
lives in its own module rather than repositories/__init__.py.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zeroshield.db.models import RunEventORM, RunORM
from zeroshield.models.enums import RunEventType
from zeroshield.repositories.run_repository import RunEvent, RunRepository


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PostgresRunRepository(RunRepository):
    """The structured system-of-record for run lifecycle events, per the V2
    Platform Foundation phase. Never a safety authority: it only records
    what worker.processor/api.routes.experiments report after
    SafetyPolicy/ExperimentRunner have already decided the outcome."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record_event(
        self,
        run_id: str,
        experiment_id: str,
        event_type: RunEventType,
        *,
        execution_context: str | None = None,
        detail: dict[str, Any] | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> RunEvent:
        occurred_at = clock()
        with self._session_factory() as session:
            run = session.get(RunORM, run_id)
            if run is None:
                run = RunORM(
                    job_id=run_id,
                    experiment_id=experiment_id,
                    execution_context=execution_context or "",
                    current_status=event_type.value,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
                session.add(run)
            else:
                run.current_status = event_type.value
                run.updated_at = occurred_at
                if execution_context is not None:
                    run.execution_context = execution_context

            session.add(
                RunEventORM(
                    job_id=run_id,
                    experiment_id=experiment_id,
                    event_type=event_type.value,
                    occurred_at=occurred_at,
                    detail=detail,
                )
            )
            session.commit()

        return RunEvent(
            run_id=run_id,
            experiment_id=experiment_id,
            event_type=event_type,
            occurred_at=occurred_at,
            detail=detail,
        )

    def list_events(self, run_id: str) -> list[RunEvent]:
        with self._session_factory() as session:
            rows = (
                session.execute(
                    select(RunEventORM)
                    .where(RunEventORM.job_id == run_id)
                    .order_by(RunEventORM.occurred_at, RunEventORM.id)
                )
                .scalars()
                .all()
            )
            return [
                RunEvent(
                    run_id=row.job_id,
                    experiment_id=row.experiment_id,
                    event_type=RunEventType(row.event_type),
                    occurred_at=row.occurred_at,
                    detail=row.detail,
                )
                for row in rows
            ]
