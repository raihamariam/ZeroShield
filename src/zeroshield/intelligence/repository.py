"""PostgreSQL-backed persistence for the threat-intelligence system of record
(Step 1's Vulnerability/VulnerabilitySource/VulnerabilityScore-history/
VendorAdvisory/Product/AffectedProduct/IntelligenceSync/ValidationCandidate
entities). Works against any SQLAlchemy-supported engine - Postgres in
production, in-memory SQLite in tests - exactly like
zeroshield.repositories.postgres_run_repository.PostgresRunRepository, which
this mirrors structurally.

Unlike RunRepository (Phase 1, optional/auxiliary observability), this
repository IS the system of record Step 1 requires - there is no "Null"
variant, since a sync without a configured DATABASE_URL has nothing
meaningful to do (zeroshield.intelligence.sync_service raises a clear error
in that case rather than silently discarding fetched intelligence).
"""

from collections.abc import Sequence
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from zeroshield.db.models import (
    AffectedProductORM,
    IntelligenceSyncORM,
    ProductORM,
    ValidationCandidateORM,
    VendorAdvisoryORM,
    VulnerabilityHistoryORM,
    VulnerabilityORM,
    VulnerabilitySourceORM,
)
from zeroshield.models.enums import Domain, ZeroClickRelevance
from zeroshield.models.vulnerability import (
    IntelligenceSync,
    IntelligenceSyncStatus,
    PriorityLabel,
    SupportStatus,
    ValidationCandidate,
    VendorAdvisory,
    Vulnerability,
    VulnerabilityHistoryEntry,
    VulnerabilitySourceName,
    VulnerabilitySourceRecord,
)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _as_utc_optional(value: datetime | None) -> datetime | None:
    return None if value is None else _as_utc(value)


def _advisory_from_orm(row: VendorAdvisoryORM) -> VendorAdvisory:
    return VendorAdvisory(
        advisory_id=row.advisory_id, source=VulnerabilitySourceName(row.source), cve_id=row.cve_id,
        title=row.title, summary=row.summary, severity=row.severity,
        published_at=_as_utc_optional(row.published_at), updated_at=_as_utc_optional(row.updated_at),
        references=row.references or [],
    )


def _vuln_from_orm(row: VulnerabilityORM) -> Vulnerability:
    return Vulnerability(
        cve_id=row.cve_id,
        description=row.description,
        published_at=_as_utc_optional(row.published_at),
        last_modified_at=_as_utc_optional(row.last_modified_at),
        cvss_score=row.cvss_score,
        cvss_vector=row.cvss_vector,
        cvss_version=row.cvss_version,
        epss_score=row.epss_score,
        epss_percentile=row.epss_percentile,
        epss_date=date.fromisoformat(row.epss_date) if row.epss_date else None,
        kev_listed=row.kev_listed,
        kev_date_added=date.fromisoformat(row.kev_date_added) if row.kev_date_added else None,
        kev_due_date=date.fromisoformat(row.kev_due_date) if row.kev_due_date else None,
        kev_known_ransomware=row.kev_known_ransomware,
        cwe_ids=list(row.cwe_ids or []),
        vendor=row.vendor,
        domain_guess=Domain(row.domain_guess) if row.domain_guess else None,
        zero_click_relevance=ZeroClickRelevance(row.zero_click_relevance) if row.zero_click_relevance else None,
        references=list(row.references or []),  # type: ignore[arg-type]
        sources=[VulnerabilitySourceName(s) for s in (row.sources or [])],
        first_seen_at=_as_utc(row.first_seen_at),
        last_updated_at=_as_utc(row.last_updated_at),
    )


class VulnerabilityRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # -- Vulnerability -----------------------------------------------------

    def get_vulnerability(self, cve_id: str) -> Vulnerability | None:
        with self._session_factory() as session:
            row = session.get(VulnerabilityORM, cve_id)
            return _vuln_from_orm(row) if row else None

    def upsert_vulnerability(self, vulnerability: Vulnerability) -> None:
        with self._session_factory() as session:
            row = session.get(VulnerabilityORM, vulnerability.cve_id)
            if row is None:
                row = VulnerabilityORM(cve_id=vulnerability.cve_id)
                session.add(row)
            row.description = vulnerability.description
            row.published_at = vulnerability.published_at
            row.last_modified_at = vulnerability.last_modified_at
            row.cvss_score = vulnerability.cvss_score
            row.cvss_vector = vulnerability.cvss_vector
            row.cvss_version = vulnerability.cvss_version
            row.epss_score = vulnerability.epss_score
            row.epss_percentile = vulnerability.epss_percentile
            row.epss_date = vulnerability.epss_date.isoformat() if vulnerability.epss_date else None
            row.kev_listed = vulnerability.kev_listed
            row.kev_date_added = (
                vulnerability.kev_date_added.isoformat() if vulnerability.kev_date_added else None
            )
            row.kev_due_date = vulnerability.kev_due_date.isoformat() if vulnerability.kev_due_date else None
            row.kev_known_ransomware = vulnerability.kev_known_ransomware
            row.cwe_ids = vulnerability.cwe_ids
            row.vendor = vulnerability.vendor
            row.domain_guess = vulnerability.domain_guess.value if vulnerability.domain_guess else None
            row.zero_click_relevance = (
                vulnerability.zero_click_relevance.value if vulnerability.zero_click_relevance else None
            )
            row.references = [str(r) for r in vulnerability.references]
            row.sources = [s.value for s in vulnerability.sources]
            row.first_seen_at = vulnerability.first_seen_at
            row.last_updated_at = vulnerability.last_updated_at
            session.commit()

    def list_vulnerabilities(
        self,
        *,
        domain: Domain | None = None,
        kev: bool | None = None,
        cvss_gte: float | None = None,
        epss_gte: float | None = None,
        vendor: str | None = None,
        product: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Vulnerability], int]:
        with self._session_factory() as session:
            stmt = select(VulnerabilityORM)
            if domain is not None:
                stmt = stmt.where(VulnerabilityORM.domain_guess == domain.value)
            if kev is not None:
                stmt = stmt.where(VulnerabilityORM.kev_listed == kev)
            if cvss_gte is not None:
                stmt = stmt.where(VulnerabilityORM.cvss_score >= cvss_gte)
            if epss_gte is not None:
                stmt = stmt.where(VulnerabilityORM.epss_score >= epss_gte)
            if vendor is not None:
                stmt = stmt.where(VulnerabilityORM.vendor.ilike(f"%{vendor}%"))
            if product is not None:
                product_cve_ids = select(AffectedProductORM.cve_id).join(
                    ProductORM, AffectedProductORM.product_id == ProductORM.id
                ).where(ProductORM.name.ilike(f"%{product}%"))
                stmt = stmt.where(VulnerabilityORM.cve_id.in_(product_cve_ids))

            total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = session.execute(
                stmt.order_by(VulnerabilityORM.last_updated_at.desc()).limit(limit).offset(offset)
            ).scalars().all()
            return [_vuln_from_orm(r) for r in rows], total

    # -- Source records + history -------------------------------------------

    def upsert_source_record(self, record: VulnerabilitySourceRecord) -> None:
        with self._session_factory() as session:
            existing = session.execute(
                select(VulnerabilitySourceORM).where(
                    VulnerabilitySourceORM.cve_id == record.cve_id,
                    VulnerabilitySourceORM.source == record.source.value,
                )
            ).scalar_one_or_none()
            if existing is None:
                existing = VulnerabilitySourceORM(
                    cve_id=record.cve_id, source=record.source.value, first_seen_at=record.first_seen_at
                )
                session.add(existing)
            existing.source_identifier = record.source_identifier
            existing.description = record.description
            existing.published_at = record.published_at
            existing.last_modified_at = record.last_modified_at
            existing.cvss_score = record.cvss_score
            existing.cvss_vector = record.cvss_vector
            existing.cvss_version = record.cvss_version
            existing.epss_score = record.epss_score
            existing.epss_percentile = record.epss_percentile
            existing.kev_listed = record.kev_listed
            existing.kev_date_added = record.kev_date_added.isoformat() if record.kev_date_added else None
            existing.kev_due_date = record.kev_due_date.isoformat() if record.kev_due_date else None
            existing.cwe_ids = record.cwe_ids
            existing.vendor = record.vendor
            existing.references = record.references
            existing.last_seen_at = record.last_seen_at
            session.commit()

    def get_sources(self, cve_id: str) -> list[VulnerabilitySourceRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(VulnerabilitySourceORM).where(VulnerabilitySourceORM.cve_id == cve_id)
            ).scalars().all()
            return [
                VulnerabilitySourceRecord(
                    cve_id=r.cve_id,
                    source=VulnerabilitySourceName(r.source),
                    source_identifier=r.source_identifier,
                    description=r.description,
                    published_at=r.published_at,
                    last_modified_at=r.last_modified_at,
                    cvss_score=r.cvss_score,
                    cvss_vector=r.cvss_vector,
                    cvss_version=r.cvss_version,
                    epss_score=r.epss_score,
                    epss_percentile=r.epss_percentile,
                    kev_listed=r.kev_listed,
                    kev_date_added=date.fromisoformat(r.kev_date_added) if r.kev_date_added else None,
                    kev_due_date=date.fromisoformat(r.kev_due_date) if r.kev_due_date else None,
                    cwe_ids=list(r.cwe_ids or []),
                    vendor=r.vendor,
                    references=list(r.references or []),
                    first_seen_at=r.first_seen_at,
                    last_seen_at=r.last_seen_at,
                )
                for r in rows
            ]

    def append_history(self, entries: Sequence[VulnerabilityHistoryEntry]) -> None:
        if not entries:
            return
        with self._session_factory() as session:
            for entry in entries:
                session.add(
                    VulnerabilityHistoryORM(
                        cve_id=entry.cve_id,
                        source=entry.source.value,
                        field=entry.field,
                        old_value=entry.old_value,
                        new_value=entry.new_value,
                        observed_at=entry.observed_at,
                    )
                )
            session.commit()

    def get_history(self, cve_id: str) -> list[VulnerabilityHistoryEntry]:
        with self._session_factory() as session:
            rows = session.execute(
                select(VulnerabilityHistoryORM)
                .where(VulnerabilityHistoryORM.cve_id == cve_id)
                .order_by(VulnerabilityHistoryORM.observed_at, VulnerabilityHistoryORM.id)
            ).scalars().all()
            return [
                VulnerabilityHistoryEntry(
                    cve_id=r.cve_id,
                    source=VulnerabilitySourceName(r.source),
                    field=r.field,
                    old_value=r.old_value,
                    new_value=r.new_value,
                    observed_at=_as_utc(r.observed_at),
                )
                for r in rows
            ]

    def get_vulnerability_as_of(self, cve_id: str, at: datetime) -> dict[str, Any] | None:
        """Reconstructs field values as of a point in time (Step 6: "what was
        known at approval/run time") by replaying vulnerability_history,
        taking the latest new_value per field observed at or before `at`.
        Returns a plain field->value dict (not a full Vulnerability, since
        older snapshots may legitimately lack fields never yet observed).

        SQLite (used in tests) does not round-trip tzinfo on DateTime(timezone=True)
        columns - reads back a naive datetime even though it was written as
        UTC-aware; Postgres does not have this quirk. _as_utc normalises both
        sides so the comparison is always well-defined regardless of backend.
        """
        history = self.get_history(cve_id)
        at_utc = _as_utc(at)
        as_of: dict[str, str | None] = {}
        seen_any = False
        for entry in history:
            if _as_utc(entry.observed_at) <= at_utc:
                as_of[entry.field] = entry.new_value
                seen_any = True
        if not seen_any:
            return None
        return as_of

    # -- Products -------------------------------------------------------

    def upsert_products(self, cve_id: str, products: Sequence[tuple[str, str, str | None]]) -> None:
        with self._session_factory() as session:
            for vendor, name, version_range in products:
                product = session.execute(
                    select(ProductORM).where(ProductORM.vendor == vendor, ProductORM.name == name)
                ).scalar_one_or_none()
                if product is None:
                    product = ProductORM(vendor=vendor, name=name)
                    session.add(product)
                    session.flush()
                link = session.execute(
                    select(AffectedProductORM).where(
                        AffectedProductORM.cve_id == cve_id, AffectedProductORM.product_id == product.id
                    )
                ).scalar_one_or_none()
                if link is None:
                    session.add(
                        AffectedProductORM(cve_id=cve_id, product_id=product.id, version_range=version_range)
                    )
                elif version_range is not None:
                    link.version_range = version_range
            session.commit()

    # -- Vendor advisories -------------------------------------------------

    def upsert_vendor_advisory(self, advisory: VendorAdvisory) -> None:
        with self._session_factory() as session:
            row = session.get(VendorAdvisoryORM, advisory.advisory_id)
            if row is None:
                row = VendorAdvisoryORM(advisory_id=advisory.advisory_id)
                session.add(row)
            row.source = advisory.source.value
            row.cve_id = advisory.cve_id
            row.title = advisory.title
            row.summary = advisory.summary
            row.severity = advisory.severity
            row.published_at = advisory.published_at
            row.updated_at = advisory.updated_at
            row.references = advisory.references
            session.commit()

    def get_advisories_for_cve(self, cve_id: str) -> list[VendorAdvisory]:
        """Retrieval counterpart to upsert_vendor_advisory (Step 3): advisories
        are persisted on every sync but had no way to be read back before this -
        neither the mitigation-gap AI route nor any endpoint could see them."""
        with self._session_factory() as session:
            rows = session.execute(
                select(VendorAdvisoryORM)
                .where(VendorAdvisoryORM.cve_id == cve_id)
                .order_by(VendorAdvisoryORM.published_at.desc().nulls_last())
            ).scalars().all()
            return [_advisory_from_orm(r) for r in rows]

    def list_vendor_advisories(self, *, source: VulnerabilitySourceName | None = None, limit: int = 100) -> list[VendorAdvisory]:
        with self._session_factory() as session:
            stmt = select(VendorAdvisoryORM)
            if source is not None:
                stmt = stmt.where(VendorAdvisoryORM.source == source.value)
            rows = session.execute(
                stmt.order_by(VendorAdvisoryORM.published_at.desc().nulls_last()).limit(limit)
            ).scalars().all()
            return [_advisory_from_orm(r) for r in rows]

    # -- Validation candidates ----------------------------------------------

    def upsert_validation_candidate(self, candidate: ValidationCandidate) -> None:
        with self._session_factory() as session:
            existing = session.execute(
                select(ValidationCandidateORM).where(
                    ValidationCandidateORM.cve_id == candidate.cve_id,
                    ValidationCandidateORM.domain == (candidate.domain.value if candidate.domain else None),
                )
            ).scalar_one_or_none()
            if existing is None:
                existing = ValidationCandidateORM(
                    cve_id=candidate.cve_id, domain=candidate.domain.value if candidate.domain else None
                )
                session.add(existing)
            existing.support_status = candidate.support_status.value
            existing.priority_score = candidate.priority_score
            existing.priority_label = candidate.priority_label.value
            existing.explanation = candidate.explanation
            existing.existing_experiment_ids = candidate.existing_experiment_ids
            existing.generated_at = candidate.generated_at
            session.commit()

    def list_priority_queue(
        self,
        *,
        domain: Domain | None = None,
        support_status: SupportStatus | None = None,
        priority_gte: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ValidationCandidate], int]:
        with self._session_factory() as session:
            stmt = select(ValidationCandidateORM)
            if domain is not None:
                stmt = stmt.where(ValidationCandidateORM.domain == domain.value)
            if support_status is not None:
                stmt = stmt.where(ValidationCandidateORM.support_status == support_status.value)
            if priority_gte is not None:
                stmt = stmt.where(ValidationCandidateORM.priority_score >= priority_gte)

            total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = session.execute(
                stmt.order_by(ValidationCandidateORM.priority_score.desc()).limit(limit).offset(offset)
            ).scalars().all()
            return [
                ValidationCandidate(
                    cve_id=r.cve_id,
                    domain=Domain(r.domain) if r.domain else None,
                    support_status=SupportStatus(r.support_status),
                    priority_score=r.priority_score,
                    priority_label=PriorityLabel(r.priority_label),
                    explanation=list(r.explanation or []),
                    existing_experiment_ids=list(r.existing_experiment_ids or []),
                    generated_at=r.generated_at,
                )
                for r in rows
            ], total

    # -- Intelligence syncs --------------------------------------------------

    def save_sync(self, sync: IntelligenceSync) -> None:
        with self._session_factory() as session:
            row = session.get(IntelligenceSyncORM, sync.sync_id)
            if row is None:
                row = IntelligenceSyncORM(sync_id=sync.sync_id)
                session.add(row)
            row.source = sync.source.value
            row.status = sync.status.value
            row.since = sync.since
            row.started_at = sync.started_at
            row.completed_at = sync.completed_at
            row.fetched_count = sync.fetched_count
            row.created_count = sync.created_count
            row.updated_count = sync.updated_count
            row.unchanged_count = sync.unchanged_count
            row.failed_count = sync.failed_count
            row.error_summary = sync.error_summary
            session.commit()

    def get_sync(self, sync_id: str) -> IntelligenceSync | None:
        with self._session_factory() as session:
            row = session.get(IntelligenceSyncORM, sync_id)
            return _sync_from_orm(row) if row else None

    def list_syncs(self, *, limit: int = 50, offset: int = 0) -> list[IntelligenceSync]:
        with self._session_factory() as session:
            rows = session.execute(
                select(IntelligenceSyncORM)
                .order_by(IntelligenceSyncORM.started_at.desc())
                .limit(limit)
                .offset(offset)
            ).scalars().all()
            return [_sync_from_orm(r) for r in rows]


def _sync_from_orm(row: IntelligenceSyncORM) -> IntelligenceSync:
    return IntelligenceSync(
        sync_id=row.sync_id,
        source=VulnerabilitySourceName(row.source),
        status=IntelligenceSyncStatus(row.status),
        since=row.since,
        started_at=row.started_at,
        completed_at=row.completed_at,
        fetched_count=row.fetched_count,
        created_count=row.created_count,
        updated_count=row.updated_count,
        unchanged_count=row.unchanged_count,
        failed_count=row.failed_count,
        error_summary=row.error_summary,
    )
