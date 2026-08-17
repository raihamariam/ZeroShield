"""Orchestrates one connector sync end-to-end (Step 7): fetch -> normalise ->
dedupe/merge -> persist -> history -> (optionally) regenerate
ValidationCandidates for every touched CVE. Deliberately independent of
RabbitMQ, exactly like zeroshield.worker.processor.process_run_job is
independent of pika - the worker's consume loop is the only thing that knows
about messaging (zeroshield.worker.intelligence_main), and it just calls
run_sync() per message. Directly testable without a broker or a real
upstream connector (inject a fake ThreatIntelligenceConnector).
"""

import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from zeroshield.experiments.discovery import discover_experiments
from zeroshield.intelligence.candidates import generate_candidate
from zeroshield.intelligence.connectors.base import ThreatIntelligenceConnector
from zeroshield.intelligence.connectors.http import ConnectorFetchError
from zeroshield.intelligence.connectors.vendor_advisory import VendorAdvisoryConnector
from zeroshield.intelligence.dedup import merge
from zeroshield.intelligence.normalisation import (
    NormalisationError,
    normalise,
    normalise_vendor_advisory,
)
from zeroshield.intelligence.priority import DEFAULT_WEIGHTS, PriorityWeights
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.models.vulnerability import IntelligenceSync, IntelligenceSyncStatus
from zeroshield.observability.metrics import INTELLIGENCE_SYNCS_TOTAL

logger = logging.getLogger("zeroshield.intelligence")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def build_experiment_ids_by_cve(experiments_dir: Path) -> dict[str, list[str]]:
    """cve_id -> experiment_id(s) of any ExperimentDefinition citing it in
    related_cves. Public so callers outside this module (e.g. the CVE
    correlation routes, which need it to populate correlate()'s
    "historical experiment links" signal - Step 4) can reuse the same
    discovery-backed mapping instead of re-deriving it."""
    mapping: dict[str, list[str]] = defaultdict(list)
    for experiment in discover_experiments(experiments_dir).experiments:
        for cve in experiment.related_cves:
            mapping[cve.cve_id].append(experiment.experiment_id)
    return dict(mapping)


_build_experiment_ids_by_cve = build_experiment_ids_by_cve


def run_sync(
    connector: ThreatIntelligenceConnector,
    *,
    sync_id: str,
    repository: VulnerabilityRepository,
    since: datetime | None = None,
    experiments_dir: Path | None = None,
    regenerate_candidates: bool = True,
    weights: PriorityWeights = DEFAULT_WEIGHTS,
    clock: Callable[[], datetime] = _utc_now,
) -> IntelligenceSync:
    started_at = clock()
    repository.save_sync(
        IntelligenceSync(
            sync_id=sync_id,
            source=connector.source,
            status=IntelligenceSyncStatus.RUNNING,
            since=since,
            started_at=started_at,
        )
    )

    fetched = created = updated = unchanged = failed = 0
    error_messages: list[str] = []
    touched_cve_ids: set[str] = set()

    try:
        for record in connector.fetch(since=since):
            fetched += 1
            try:
                if isinstance(connector, VendorAdvisoryConnector):
                    advisory, contribution = normalise_vendor_advisory(record)
                    repository.upsert_vendor_advisory(advisory)
                    if contribution is None:
                        unchanged += 1  # advisory persisted, but no CVE to link/merge
                        continue
                else:
                    contribution = normalise(record)

                existing = repository.get_vulnerability(contribution.cve_id)
                result = merge(existing, contribution, clock=clock)
                repository.upsert_vulnerability(result.vulnerability)
                repository.upsert_source_record(result.source_record)
                repository.append_history(result.history)
                if result.products:
                    repository.upsert_products(contribution.cve_id, result.products)

                touched_cve_ids.add(contribution.cve_id)
                if result.is_new:
                    created += 1
                elif result.history:
                    updated += 1
                else:
                    unchanged += 1
            except (NormalisationError, ValidationError) as exc:
                failed += 1
                error_messages.append(str(exc))
                logger.warning("sync %s: record failed normalisation/validation: %s", sync_id, exc)
    except ConnectorFetchError as exc:
        completed_at = clock()
        sync = IntelligenceSync(
            sync_id=sync_id,
            source=connector.source,
            status=IntelligenceSyncStatus.FAILED,
            since=since,
            started_at=started_at,
            completed_at=completed_at,
            fetched_count=fetched,
            created_count=created,
            updated_count=updated,
            unchanged_count=unchanged,
            failed_count=failed,
            error_summary=str(exc),
        )
        repository.save_sync(sync)
        INTELLIGENCE_SYNCS_TOTAL.labels(source=connector.source.value, status=sync.status.value).inc()
        return sync

    if regenerate_candidates and touched_cve_ids:
        experiment_ids_by_cve = (
            _build_experiment_ids_by_cve(experiments_dir) if experiments_dir is not None else {}
        )
        for cve_id in touched_cve_ids:
            vulnerability = repository.get_vulnerability(cve_id)
            if vulnerability is None:
                continue
            candidate = generate_candidate(
                vulnerability, experiment_ids_by_cve=experiment_ids_by_cve, weights=weights, clock=clock
            )
            if candidate is not None:
                repository.upsert_validation_candidate(candidate)

    completed_at = clock()
    if fetched == 0 or failed == 0:
        status = IntelligenceSyncStatus.COMPLETED
    elif failed < fetched:
        status = IntelligenceSyncStatus.PARTIAL
    else:
        status = IntelligenceSyncStatus.FAILED

    sync = IntelligenceSync(
        sync_id=sync_id,
        source=connector.source,
        status=status,
        since=since,
        started_at=started_at,
        completed_at=completed_at,
        fetched_count=fetched,
        created_count=created,
        updated_count=updated,
        unchanged_count=unchanged,
        failed_count=failed,
        error_summary="; ".join(error_messages[:10]) if error_messages else None,
    )
    repository.save_sync(sync)
    INTELLIGENCE_SYNCS_TOTAL.labels(source=connector.source.value, status=sync.status.value).inc()
    return sync
