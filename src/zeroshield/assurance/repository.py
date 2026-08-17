"""PostgreSQL-backed persistence for the assurance package (V2 Phase 5).
Works against any SQLAlchemy-supported engine (Postgres in production,
in-memory SQLite in tests), mirroring zeroshield.intelligence.repository.
VulnerabilityRepository and zeroshield.studio.repository.
ExperimentVersionRepository structurally: one repository class over the
package's small set of related tables.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zeroshield.assurance.models import (
    AIAssessmentRecord,
    Asset,
    Control,
    ControlValidation,
    ControlVersion,
    RevalidationCandidate,
)
from zeroshield.db.models import (
    AffectedProductORM,
    AIAssessmentORM,
    AssetORM,
    ControlORM,
    ControlValidationORM,
    ControlVersionORM,
    ProductORM,
    RevalidationCandidateORM,
)


def control_id_for(domain: str, mitigation_strategy_id: str) -> str:
    """Deterministic Control identity: a control IS "this mitigation
    strategy, in this domain" - see zeroshield.assurance.models.Control."""
    return f"{domain.strip().upper()}:{mitigation_strategy_id.strip()}"


def _as_utc(value: datetime) -> datetime:
    """SQLite (used in tests) does not round-trip tzinfo on
    DateTime(timezone=True) columns - reads back a naive datetime even
    though it was written as UTC-aware; Postgres does not have this quirk.
    Mirrors zeroshield.intelligence.repository._as_utc exactly - split from a
    single Optional-accepting version so mypy can tell non-nullable columns
    (created_at/updated_at/validated_at) apart from genuinely-nullable ones
    (reviewed_at) at the type level, matching that module's convention."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _as_utc_optional(value: datetime | None) -> datetime | None:
    return None if value is None else _as_utc(value)


def _asset_from_orm(row: AssetORM) -> Asset:
    return Asset(
        asset_id=row.asset_id, name=row.name, vendor=row.vendor, product=row.product, version=row.version,
        environment=row.environment, exposure=row.exposure, criticality=row.criticality, active=row.active,
        created_at=_as_utc(row.created_at), updated_at=_as_utc(row.updated_at),
    )


def _control_from_orm(row: ControlORM) -> Control:
    return Control(
        control_id=row.control_id, name=row.name, domain=row.domain,
        mitigation_strategy_id=row.mitigation_strategy_id, created_at=_as_utc(row.created_at),
    )


def _version_from_orm(row: ControlVersionORM) -> ControlVersion:
    return ControlVersion(
        version_id=row.version_id, control_id=row.control_id, version_label=row.version_label,
        domain_pack_id=row.domain_pack_id, template_id=row.template_id, template_version=row.template_version,
        created_at=_as_utc(row.created_at),
    )


def _validation_from_orm(row: ControlValidationORM) -> ControlValidation:
    return ControlValidation(
        validation_id=row.validation_id, control_id=row.control_id, version_id=row.version_id,
        experiment_id=row.experiment_id, baseline_run_id=row.baseline_run_id,
        mitigation_run_id=row.mitigation_run_id, total_cases=row.total_cases,
        block_rate_improvement=row.block_rate_improvement, false_positive_rate=row.false_positive_rate,
        false_negative_rate=row.false_negative_rate, valid_acceptance_rate=row.valid_acceptance_rate,
        parser_reach_rate=row.parser_reach_rate, latency_overhead_ms=row.latency_overhead_ms,
        verdict_label=row.verdict_label, validated_at=_as_utc(row.validated_at),
    )


def _candidate_from_orm(row: RevalidationCandidateORM) -> RevalidationCandidate:
    return RevalidationCandidate(
        candidate_id=row.candidate_id, control_id=row.control_id, experiment_id=row.experiment_id,
        trigger_type=row.trigger_type, trigger_detail=row.trigger_detail, status=row.status,
        created_at=_as_utc(row.created_at), reviewed_by=row.reviewed_by,
        reviewed_at=_as_utc_optional(row.reviewed_at), review_note=row.review_note,
    )


def _assessment_from_orm(row: AIAssessmentORM) -> AIAssessmentRecord:
    return AIAssessmentRecord(
        assessment_id=row.assessment_id, assessment_type=row.assessment_type, subject_type=row.subject_type,
        subject_id=row.subject_id, payload=row.payload, confidence=row.confidence, reviewed=row.reviewed,
        reviewed_by=row.reviewed_by, reviewed_at=_as_utc_optional(row.reviewed_at), review_note=row.review_note,
        created_at=_as_utc(row.created_at),
    )


class AssuranceRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Assets (Step 7) --------------------------------------------------

    def create_asset(self, asset: Asset) -> Asset:
        with self._session_factory() as session:
            session.add(
                AssetORM(
                    asset_id=asset.asset_id, name=asset.name, vendor=asset.vendor, product=asset.product,
                    version=asset.version, environment=asset.environment, exposure=asset.exposure,
                    criticality=asset.criticality, active=asset.active, created_at=asset.created_at,
                    updated_at=asset.updated_at,
                )
            )
            session.commit()
        return asset

    def get_asset(self, asset_id: str) -> Asset | None:
        with self._session_factory() as session:
            row = session.get(AssetORM, asset_id)
            return _asset_from_orm(row) if row is not None else None

    def list_assets(self, *, active: bool | None = None, vendor: str | None = None) -> list[Asset]:
        with self._session_factory() as session:
            stmt = select(AssetORM)
            if active is not None:
                stmt = stmt.where(AssetORM.active == active)
            if vendor is not None:
                stmt = stmt.where(AssetORM.vendor.ilike(f"%{vendor}%"))
            rows = session.execute(stmt.order_by(AssetORM.name)).scalars().all()
            return [_asset_from_orm(r) for r in rows]

    def update_asset(self, asset_id: str, **fields: object) -> Asset | None:
        with self._session_factory() as session:
            row = session.get(AssetORM, asset_id)
            if row is None:
                return None
            for key, value in fields.items():
                setattr(row, key, value)
            row.updated_at = datetime.now(UTC)
            session.commit()
            return _asset_from_orm(row)

    def list_potentially_affected_assets(self, cve_id: str) -> list[Asset]:
        """Deterministic linking rule (Step 7): an asset is potentially
        affected by a CVE when its (vendor, product) matches one of the
        CVE's known affected products (zeroshield.db.models.
        AffectedProductORM/ProductORM, populated by the same NVD ingestion
        that already backs GET /vulnerabilities' `product` filter). No AI,
        no fuzzy version-range logic - a real, explainable join."""
        with self._session_factory() as session:
            product_pairs = session.execute(
                select(ProductORM.vendor, ProductORM.name)
                .join(AffectedProductORM, AffectedProductORM.product_id == ProductORM.id)
                .where(AffectedProductORM.cve_id == cve_id)
            ).all()
            if not product_pairs:
                return []
            rows: list[AssetORM] = []
            seen: set[str] = set()
            for vendor, product in product_pairs:
                matches = session.execute(
                    select(AssetORM).where(
                        AssetORM.vendor.ilike(vendor), AssetORM.product.ilike(f"%{product}%")
                    )
                ).scalars().all()
                for m in matches:
                    if m.asset_id not in seen:
                        seen.add(m.asset_id)
                        rows.append(m)
            return [_asset_from_orm(r) for r in rows]

    # -- Controls / control versions (Step 8) ------------------------------

    def get_or_create_control(self, *, domain: str, mitigation_strategy_id: str, name: str) -> Control:
        cid = control_id_for(domain, mitigation_strategy_id)
        with self._session_factory() as session:
            row = session.get(ControlORM, cid)
            if row is None:
                row = ControlORM(
                    control_id=cid, name=name, domain=domain, mitigation_strategy_id=mitigation_strategy_id,
                    created_at=datetime.now(UTC),
                )
                session.add(row)
                session.commit()
            return _control_from_orm(row)

    def get_control(self, control_id: str) -> Control | None:
        with self._session_factory() as session:
            row = session.get(ControlORM, control_id)
            return _control_from_orm(row) if row is not None else None

    def list_controls(self) -> list[Control]:
        with self._session_factory() as session:
            rows = session.execute(select(ControlORM).order_by(ControlORM.name)).scalars().all()
            return [_control_from_orm(r) for r in rows]

    def get_or_create_control_version(
        self, *, control_id: str, version_label: str, domain_pack_id: str, template_id: str, template_version: str
    ) -> ControlVersion:
        with self._session_factory() as session:
            row = session.execute(
                select(ControlVersionORM).where(
                    ControlVersionORM.control_id == control_id, ControlVersionORM.version_label == version_label
                )
            ).scalar_one_or_none()
            if row is None:
                row = ControlVersionORM(
                    version_id=f"CV-{uuid.uuid4().hex}", control_id=control_id, version_label=version_label,
                    domain_pack_id=domain_pack_id, template_id=template_id, template_version=template_version,
                    created_at=datetime.now(UTC),
                )
                session.add(row)
                session.commit()
            return _version_from_orm(row)

    def list_control_versions(self, control_id: str) -> list[ControlVersion]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ControlVersionORM)
                .where(ControlVersionORM.control_id == control_id)
                .order_by(ControlVersionORM.created_at)
            ).scalars().all()
            return [_version_from_orm(r) for r in rows]

    # -- Control validations (Step 8/9) - append-only ----------------------

    def record_validation(self, validation: ControlValidation) -> ControlValidation:
        with self._session_factory() as session:
            session.add(
                ControlValidationORM(
                    validation_id=validation.validation_id, control_id=validation.control_id,
                    version_id=validation.version_id, experiment_id=validation.experiment_id,
                    baseline_run_id=validation.baseline_run_id, mitigation_run_id=validation.mitigation_run_id,
                    total_cases=validation.total_cases, block_rate_improvement=validation.block_rate_improvement,
                    false_positive_rate=validation.false_positive_rate,
                    false_negative_rate=validation.false_negative_rate,
                    valid_acceptance_rate=validation.valid_acceptance_rate,
                    parser_reach_rate=validation.parser_reach_rate,
                    latency_overhead_ms=validation.latency_overhead_ms, verdict_label=validation.verdict_label,
                    validated_at=validation.validated_at,
                )
            )
            session.commit()
        return validation

    def list_validations(self, control_id: str) -> list[ControlValidation]:
        """Oldest -> newest, the natural order for a trend line."""
        with self._session_factory() as session:
            rows = session.execute(
                select(ControlValidationORM)
                .where(ControlValidationORM.control_id == control_id)
                .order_by(ControlValidationORM.validated_at)
            ).scalars().all()
            return [_validation_from_orm(r) for r in rows]

    # -- Revalidation candidates (Step 11) ----------------------------------

    def find_pending_candidate(self, *, control_id: str, trigger_type: str) -> RevalidationCandidate | None:
        """Duplicate-prevention check (Step 11): never create a second
        pending candidate for the same control+trigger while one is already
        pending. Keyed on (control_id, trigger_type) only - trigger_detail
        is deliberately excluded because it can embed values that change on
        every scan (e.g. "last validated N days ago", which increments
        daily), and matching on the full detail string would let a fresh
        duplicate slip through every time that text changes."""
        with self._session_factory() as session:
            row = session.execute(
                select(RevalidationCandidateORM).where(
                    RevalidationCandidateORM.control_id == control_id,
                    RevalidationCandidateORM.trigger_type == trigger_type,
                    RevalidationCandidateORM.status == "pending",
                )
            ).scalar_one_or_none()
            return _candidate_from_orm(row) if row is not None else None

    def create_candidate(self, candidate: RevalidationCandidate) -> RevalidationCandidate:
        with self._session_factory() as session:
            session.add(
                RevalidationCandidateORM(
                    candidate_id=candidate.candidate_id, control_id=candidate.control_id,
                    experiment_id=candidate.experiment_id, trigger_type=candidate.trigger_type,
                    trigger_detail=candidate.trigger_detail, status=candidate.status,
                    created_at=candidate.created_at,
                )
            )
            session.commit()
        return candidate

    def get_candidate(self, candidate_id: str) -> RevalidationCandidate | None:
        with self._session_factory() as session:
            row = session.get(RevalidationCandidateORM, candidate_id)
            return _candidate_from_orm(row) if row is not None else None

    def list_candidates(self, *, status: str | None = None) -> list[RevalidationCandidate]:
        with self._session_factory() as session:
            stmt = select(RevalidationCandidateORM)
            if status is not None:
                stmt = stmt.where(RevalidationCandidateORM.status == status)
            rows = session.execute(stmt.order_by(RevalidationCandidateORM.created_at.desc())).scalars().all()
            return [_candidate_from_orm(r) for r in rows]

    def update_candidate_status(
        self, candidate_id: str, *, status: str, reviewed_by: str, review_note: str | None
    ) -> RevalidationCandidate | None:
        with self._session_factory() as session:
            row = session.get(RevalidationCandidateORM, candidate_id)
            if row is None:
                return None
            row.status = status
            row.reviewed_by = reviewed_by
            row.reviewed_at = datetime.now(UTC)
            row.review_note = review_note
            session.commit()
            return _candidate_from_orm(row)

    # -- AI assessments (Step 2) --------------------------------------------

    def save_assessment(
        self, *, assessment_type: str, subject_type: str, subject_id: str, payload: dict, confidence: float
    ) -> AIAssessmentRecord:
        record = AIAssessmentRecord(
            assessment_id=f"ASSESS-{uuid.uuid4().hex}", assessment_type=assessment_type, subject_type=subject_type,
            subject_id=subject_id, payload=payload, confidence=confidence, reviewed=False,
            created_at=datetime.now(UTC),
        )
        with self._session_factory() as session:
            session.add(
                AIAssessmentORM(
                    assessment_id=record.assessment_id, assessment_type=record.assessment_type,
                    subject_type=record.subject_type, subject_id=record.subject_id, payload=record.payload,
                    confidence=record.confidence, reviewed=record.reviewed, created_at=record.created_at,
                )
            )
            session.commit()
        return record

    def get_assessment(self, assessment_id: str) -> AIAssessmentRecord | None:
        with self._session_factory() as session:
            row = session.get(AIAssessmentORM, assessment_id)
            return _assessment_from_orm(row) if row is not None else None

    def list_assessments(
        self,
        *,
        subject_type: str | None = None,
        subject_id: str | None = None,
        assessment_type: str | None = None,
        reviewed: bool | None = None,
    ) -> list[AIAssessmentRecord]:
        with self._session_factory() as session:
            stmt = select(AIAssessmentORM)
            if subject_type is not None:
                stmt = stmt.where(AIAssessmentORM.subject_type == subject_type)
            if subject_id is not None:
                stmt = stmt.where(AIAssessmentORM.subject_id == subject_id)
            if assessment_type is not None:
                stmt = stmt.where(AIAssessmentORM.assessment_type == assessment_type)
            if reviewed is not None:
                stmt = stmt.where(AIAssessmentORM.reviewed == reviewed)
            rows = session.execute(stmt.order_by(AIAssessmentORM.created_at.desc())).scalars().all()
            return [_assessment_from_orm(r) for r in rows]

    def mark_assessment_reviewed(
        self, assessment_id: str, *, reviewed_by: str, review_note: str | None
    ) -> AIAssessmentRecord | None:
        with self._session_factory() as session:
            row = session.get(AIAssessmentORM, assessment_id)
            if row is None:
                return None
            row.reviewed = True
            row.reviewed_by = reviewed_by
            row.reviewed_at = datetime.now(UTC)
            row.review_note = review_note
            session.commit()
            return _assessment_from_orm(row)
