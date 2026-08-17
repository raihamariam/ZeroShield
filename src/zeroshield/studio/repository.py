"""PostgreSQL-backed persistence for Experiment Studio versions and their
approval history - mirrors zeroshield.intelligence.repository.
VulnerabilityRepository structurally (works against any SQLAlchemy engine,
Postgres in production, in-memory SQLite in tests)."""

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zeroshield.db.models import ExperimentVersionApprovalORM, ExperimentVersionORM
from zeroshield.models import ApprovalDecision, ExperimentDefinition, ExperimentVersion
from zeroshield.models.enums import ExperimentVersionStatus


def _to_orm_fields(version: ExperimentVersion) -> dict[str, object]:
    return {
        "experiment_id": version.experiment_id,
        "version_number": version.version_number,
        "status": version.status.value,
        "domain_pack_id": version.domain_pack_id,
        "template_id": version.template_id,
        "template_version": version.template_version,
        "definition": version.definition.model_dump(mode="json"),
        "dataset_provenance": version.dataset_provenance,
        "created_by": version.created_by,
        "created_at": version.created_at,
        "updated_at": version.updated_at,
    }


def _from_orm(row: ExperimentVersionORM) -> ExperimentVersion:
    return ExperimentVersion(
        version_id=row.version_id,
        experiment_id=row.experiment_id,
        version_number=row.version_number,
        status=ExperimentVersionStatus(row.status),
        domain_pack_id=row.domain_pack_id,
        template_id=row.template_id,
        template_version=row.template_version,
        definition=ExperimentDefinition.model_validate(row.definition),
        dataset_provenance=row.dataset_provenance,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class ExperimentVersionRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save_version(self, version: ExperimentVersion) -> None:
        with self._session_factory() as session:
            row = session.get(ExperimentVersionORM, version.version_id)
            if row is None:
                row = ExperimentVersionORM(version_id=version.version_id)
                session.add(row)
            for field, value in _to_orm_fields(version).items():
                setattr(row, field, value)
            session.commit()

    def get_version(self, version_id: str) -> ExperimentVersion | None:
        with self._session_factory() as session:
            row = session.get(ExperimentVersionORM, version_id)
            return _from_orm(row) if row else None

    def list_versions(
        self, *, experiment_id: str | None = None, status: ExperimentVersionStatus | None = None
    ) -> list[ExperimentVersion]:
        with self._session_factory() as session:
            stmt = select(ExperimentVersionORM)
            if experiment_id is not None:
                stmt = stmt.where(ExperimentVersionORM.experiment_id == experiment_id)
            if status is not None:
                stmt = stmt.where(ExperimentVersionORM.status == status.value)
            rows = session.execute(
                stmt.order_by(ExperimentVersionORM.experiment_id, ExperimentVersionORM.version_number)
            ).scalars().all()
            return [_from_orm(r) for r in rows]

    def latest_version_number(self, experiment_id: str) -> int:
        versions = self.list_versions(experiment_id=experiment_id)
        return max((v.version_number for v in versions), default=0)

    def append_approval_decision(self, decision: ApprovalDecision) -> None:
        with self._session_factory() as session:
            session.add(
                ExperimentVersionApprovalORM(
                    version_id=decision.version_id,
                    from_status=decision.from_status.value,
                    to_status=decision.to_status.value,
                    actor=decision.actor,
                    reason=decision.reason,
                    decided_at=decision.decided_at,
                )
            )
            session.commit()

    def get_approval_history(self, version_id: str) -> list[ApprovalDecision]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ExperimentVersionApprovalORM)
                .where(ExperimentVersionApprovalORM.version_id == version_id)
                .order_by(ExperimentVersionApprovalORM.decided_at, ExperimentVersionApprovalORM.id)
            ).scalars().all()
            return [
                ApprovalDecision(
                    version_id=r.version_id,
                    from_status=ExperimentVersionStatus(r.from_status),
                    to_status=ExperimentVersionStatus(r.to_status),
                    actor=r.actor,
                    reason=r.reason,
                    decided_at=r.decided_at,
                )
                for r in rows
            ]
