"""Abstracts run-lifecycle persistence, per SRS-precedent Repository pattern
(mirrors zeroshield.repositories.evidence_repository.EvidenceRepository) and
the V2 Improvement Plan's "PostgreSQL becomes the structured system of
record" principle.

This is a distinct concern from EvidenceRepository: RunRepository records
*when a run moved through which lifecycle stage* (RunEventType, per
models.enums), never evidence content, never a safety decision, never an
approval. Recording a run event is always a side-effect of an
already-made decision - it is never itself a safety authority, and a
recording failure must never be allowed to block or alter the underlying
run (see NullRunRepository below, and worker.processor's best-effort
wrapping of every record_event call).

PostgresRunRepository (zeroshield.repositories.postgres_run_repository)
requires the optional "db" extra (sqlalchemy/alembic/psycopg) and is
deliberately NOT imported here, for the same reason
MinioEvidenceRepository is not imported from
zeroshield.repositories.__init__ - it would make sqlalchemy a hard
dependency for every existing CLI/dashboard/API/worker code path. Import
it directly from zeroshield.repositories.postgres_run_repository when the
db extra is installed and Postgres is actually configured.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from zeroshield.models.enums import RunEventType


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class RunEvent:
    run_id: str
    experiment_id: str
    event_type: RunEventType
    occurred_at: datetime
    detail: dict[str, Any] | None


class RunRepository(ABC):
    """Abstracts run-lifecycle event persistence. run_id here is the API's
    job_id (see zeroshield.services.job_store) - the one identifier that
    exists for the whole baseline+mitigation journey described by the V2
    Improvement Plan's Experiment Lifecycle diagram, not the per-mode
    baseline_run_id/mitigation_run_id used inside ExperimentRunner."""

    @abstractmethod
    def record_event(
        self,
        run_id: str,
        experiment_id: str,
        event_type: RunEventType,
        *,
        execution_context: str | None = None,
        detail: dict[str, Any] | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> RunEvent: ...

    @abstractmethod
    def list_events(self, run_id: str) -> list[RunEvent]: ...


class NullRunRepository(RunRepository):
    """No-op RunRepository - the default whenever no DATABASE_URL is
    configured, so every existing local/CI/test code path keeps working
    with zero Postgres dependency, per V1 compatibility. Recording an
    event is a deliberate no-op, not a silent failure: list_events
    correctly returns an empty history, since none was ever configured to
    be recorded."""

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
        return RunEvent(
            run_id=run_id,
            experiment_id=experiment_id,
            event_type=event_type,
            occurred_at=clock(),
            detail=detail,
        )

    def list_events(self, run_id: str) -> list[RunEvent]:
        return []
