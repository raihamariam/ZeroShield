"""Threat Intelligence & Prioritisation routes (V2 Phase 2, Step 10).

Every handler here is a thin wrapper over zeroshield.intelligence.repository/
sync_service - no normalisation, dedup, or priority-scoring logic is
duplicated here. POST /intelligence/sync only queues a job (mirrors
POST /experiments/{id}/runs) and never fetches from an upstream source
itself, so a slow NVD sync can never block this request.
"""

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import Path as FastAPIPath

from zeroshield.api.dependencies import get_intelligence_publisher, get_vulnerability_repository
from zeroshield.api.schemas import (
    ConnectorHealthResponse,
    PriorityQueueResponse,
    SourcesResponse,
    SyncListResponse,
    SyncRequest,
    SyncStatusResponse,
    SyncSubmittedResponse,
    ValidationCandidateResponse,
    VendorAdvisoryListResponse,
    VendorAdvisoryResponse,
    VulnerabilityDetailResponse,
    VulnerabilityHistoryEntryResponse,
    VulnerabilityHistoryResponse,
    VulnerabilityListResponse,
    VulnerabilitySourceDetail,
    VulnerabilitySummary,
)
from zeroshield.intelligence.connectors.registry import build_connector, known_sources
from zeroshield.intelligence.messaging import IntelligenceSyncJobMessage
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.models.enums import Domain
from zeroshield.models.vulnerability import (
    IntelligenceSync,
    IntelligenceSyncStatus,
    SupportStatus,
    Vulnerability,
    VulnerabilitySourceName,
)

router = APIRouter(tags=["intelligence"])
logger = logging.getLogger("zeroshield.api")

_CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,7}$"


def _summary(v: Vulnerability) -> VulnerabilitySummary:
    return VulnerabilitySummary(
        cve_id=v.cve_id,
        description=v.description,
        cvss_score=v.cvss_score,
        epss_score=v.epss_score,
        kev_listed=v.kev_listed,
        vendor=v.vendor,
        domain_guess=v.domain_guess.value if v.domain_guess else None,
        sources=[s.value for s in v.sources],
        last_updated_at=v.last_updated_at.isoformat(),
    )


def _sync_response(sync: IntelligenceSync) -> SyncStatusResponse:
    return SyncStatusResponse(
        sync_id=sync.sync_id,
        source=sync.source.value,
        status=sync.status.value,
        since=sync.since.isoformat() if sync.since else None,
        started_at=sync.started_at.isoformat(),
        completed_at=sync.completed_at.isoformat() if sync.completed_at else None,
        fetched_count=sync.fetched_count,
        created_count=sync.created_count,
        updated_count=sync.updated_count,
        unchanged_count=sync.unchanged_count,
        failed_count=sync.failed_count,
        error_summary=sync.error_summary,
    )


@router.get(
    "/vulnerabilities",
    response_model=VulnerabilityListResponse,
    summary="List ingested vulnerabilities",
    description="Paginated, filterable view of the merged threat-intelligence system of "
    "record. Includes vulnerabilities in unsupported domains - see support_status on "
    "GET /priority-queue for which ones ZeroShield can actually validate.",
)
def list_vulnerabilities(
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    domain: Annotated[Domain | None, Query()] = None,
    kev: Annotated[bool | None, Query()] = None,
    cvss_gte: Annotated[float | None, Query(ge=0.0, le=10.0)] = None,
    epss_gte: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    vendor: Annotated[str | None, Query()] = None,
    product: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> VulnerabilityListResponse:
    vulnerabilities, total = repository.list_vulnerabilities(
        domain=domain, kev=kev, cvss_gte=cvss_gte, epss_gte=epss_gte, vendor=vendor, product=product,
        limit=limit, offset=offset,
    )
    return VulnerabilityListResponse(
        vulnerabilities=[_summary(v) for v in vulnerabilities], total=total, limit=limit, offset=offset
    )


@router.get(
    "/vulnerabilities/{cve_id}",
    response_model=VulnerabilityDetailResponse,
    summary="Get one vulnerability's merged view and per-source contributions",
)
def get_vulnerability_detail(
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    cve_id: Annotated[str, FastAPIPath(pattern=_CVE_ID_PATTERN)],
) -> VulnerabilityDetailResponse:
    vulnerability = repository.get_vulnerability(cve_id)
    if vulnerability is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "vulnerability_not_found", "detail": f"no vulnerability with id '{cve_id}'"},
        )
    sources = repository.get_sources(cve_id)
    return VulnerabilityDetailResponse(
        **_summary(vulnerability).model_dump(),
        published_at=vulnerability.published_at.isoformat() if vulnerability.published_at else None,
        last_modified_at=vulnerability.last_modified_at.isoformat() if vulnerability.last_modified_at else None,
        cvss_vector=vulnerability.cvss_vector,
        cvss_version=vulnerability.cvss_version,
        epss_percentile=vulnerability.epss_percentile,
        kev_date_added=vulnerability.kev_date_added.isoformat() if vulnerability.kev_date_added else None,
        kev_due_date=vulnerability.kev_due_date.isoformat() if vulnerability.kev_due_date else None,
        cwe_ids=vulnerability.cwe_ids,
        references=[str(r) for r in vulnerability.references],
        source_records=[
            VulnerabilitySourceDetail(
                source=s.source.value,
                source_identifier=s.source_identifier,
                cvss_score=s.cvss_score,
                cvss_vector=s.cvss_vector,
                epss_score=s.epss_score,
                kev_listed=s.kev_listed,
                description=s.description,
                references=s.references,
                first_seen_at=s.first_seen_at.isoformat(),
                last_seen_at=s.last_seen_at.isoformat(),
            )
            for s in sources
        ],
    )


@router.get(
    "/vulnerabilities/{cve_id}/history",
    response_model=VulnerabilityHistoryResponse,
    summary="Field-level change history for one vulnerability",
    description="Per Step 6: what changed, from which source, and when - lets a later "
    "review answer what intelligence was known at approval/run time.",
)
def get_vulnerability_history(
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    cve_id: Annotated[str, FastAPIPath(pattern=_CVE_ID_PATTERN)],
) -> VulnerabilityHistoryResponse:
    history = repository.get_history(cve_id)
    return VulnerabilityHistoryResponse(
        cve_id=cve_id,
        history=[
            VulnerabilityHistoryEntryResponse(
                source=h.source.value, field=h.field, old_value=h.old_value, new_value=h.new_value,
                observed_at=h.observed_at.isoformat(),
            )
            for h in history
        ],
    )


@router.get(
    "/vulnerabilities/{cve_id}/advisories",
    response_model=VendorAdvisoryListResponse,
    summary="Vendor/ecosystem advisories retrieved for one CVE (Step 3 retrieval)",
    description="Read side of the advisories intelligence sync already persists via "
    "VendorAdvisoryConnector - previously write-only. Feeds the AI mitigation-gap "
    "analyst (GET .../analyst/mitigation-gap) with real grounding text instead of none.",
)
def get_vulnerability_advisories(
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    cve_id: Annotated[str, FastAPIPath(pattern=_CVE_ID_PATTERN)],
) -> VendorAdvisoryListResponse:
    advisories = repository.get_advisories_for_cve(cve_id)
    return VendorAdvisoryListResponse(
        cve_id=cve_id,
        advisories=[
            VendorAdvisoryResponse(
                advisory_id=a.advisory_id, source=a.source.value, cve_id=a.cve_id, title=a.title,
                summary=a.summary, severity=a.severity,
                published_at=a.published_at.isoformat() if a.published_at else None,
                updated_at=a.updated_at.isoformat() if a.updated_at else None, references=a.references,
            )
            for a in advisories
        ],
    )


@router.get(
    "/priority-queue",
    response_model=PriorityQueueResponse,
    summary="ZeroShield Validation Priority queue",
    description="ValidationCandidate records, most-worth-validating first. Only ever "
    "contains SUPPORTED/PARTIALLY_SUPPORTED CVEs - an UNSUPPORTED-domain CVE is visible "
    "via GET /vulnerabilities but never appears here (Step 9).",
)
def get_priority_queue(
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    domain: Annotated[Domain | None, Query()] = None,
    support_status: Annotated[SupportStatus | None, Query()] = None,
    priority_gte: Annotated[float | None, Query(ge=0.0, le=100.0)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PriorityQueueResponse:
    candidates, total = repository.list_priority_queue(
        domain=domain, support_status=support_status, priority_gte=priority_gte, limit=limit, offset=offset
    )
    return PriorityQueueResponse(
        candidates=[
            ValidationCandidateResponse(
                cve_id=c.cve_id, domain=c.domain.value if c.domain else None,
                support_status=c.support_status.value, priority_score=c.priority_score,
                priority_label=c.priority_label.value, explanation=c.explanation,
                existing_experiment_ids=c.existing_experiment_ids, generated_at=c.generated_at.isoformat(),
            )
            for c in candidates
        ],
        total=total, limit=limit, offset=offset,
    )


def _connector_health() -> list[ConnectorHealthResponse]:
    results = []
    for source in known_sources():
        health = build_connector(source).health()
        results.append(
            ConnectorHealthResponse(
                source=health.source.value, available=health.available, detail=health.detail,
                checked_at=health.checked_at.isoformat(),
            )
        )
    return results


@router.get(
    "/sources",
    response_model=SourcesResponse,
    summary="List registered intelligence sources and their reachability",
)
def list_sources() -> SourcesResponse:
    return SourcesResponse(sources=_connector_health())


@router.get(
    "/integrations",
    response_model=SourcesResponse,
    summary="Integration health (operations-facing alias of GET /sources)",
    description="Same underlying connector registry/health as GET /sources - kept as a "
    "separate route since 'integrations' is the operations-facing name used elsewhere "
    "in the V2 roadmap, while 'sources' is the data-facing name used on Vulnerability records.",
)
def list_integrations() -> SourcesResponse:
    return SourcesResponse(sources=_connector_health())


@router.post(
    "/intelligence/sync",
    response_model=SyncSubmittedResponse,
    status_code=202,
    summary="Submit an intelligence sync (asynchronous)",
    description="Queues a connector fetch on RabbitMQ and returns immediately with a "
    "sync_id. Poll GET /intelligence/syncs/{sync_id} for status and counts. Never fetches "
    "from the upstream source itself - a slow/large sync can never block this request.",
)
def submit_sync(
    request: SyncRequest,
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    publish: Annotated[Callable[[IntelligenceSyncJobMessage], None], Depends(get_intelligence_publisher)],
) -> SyncSubmittedResponse:
    try:
        source = VulnerabilitySourceName(request.source)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unknown_source",
                "detail": f"'{request.source}' is not a known source; known sources: "
                f"{sorted(s.value for s in known_sources())}",
            },
        ) from None
    if source not in known_sources():
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unregistered_source",
                "detail": f"'{source.value}' has no registered connector (e.g. manual_import is "
                "import-only, never synced)",
            },
        )

    since = None
    if request.since is not None:
        try:
            since = datetime.fromisoformat(request.since)
        except ValueError:
            raise HTTPException(
                status_code=422, detail={"error": "invalid_since", "detail": "since must be ISO-8601"}
            ) from None

    sync_id = f"SYNC-{uuid.uuid4().hex}"
    now = datetime.now(UTC)
    repository.save_sync(
        IntelligenceSync(
            sync_id=sync_id, source=source, status=IntelligenceSyncStatus.QUEUED, since=since, started_at=now
        )
    )
    publish(IntelligenceSyncJobMessage(sync_id=sync_id, source=source, since=since))
    return SyncSubmittedResponse(sync_id=sync_id, source=source.value, status=IntelligenceSyncStatus.QUEUED.value)


@router.get(
    "/intelligence/syncs",
    response_model=SyncListResponse,
    summary="List recent intelligence syncs",
)
def list_syncs(
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SyncListResponse:
    return SyncListResponse(syncs=[_sync_response(s) for s in repository.list_syncs(limit=limit, offset=offset)])


@router.get(
    "/intelligence/syncs/{sync_id}",
    response_model=SyncStatusResponse,
    summary="Get one intelligence sync's status and counts",
)
def get_sync_status(
    repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    sync_id: Annotated[str, FastAPIPath(pattern=r"^SYNC-[0-9a-f]{32}$")],
) -> SyncStatusResponse:
    sync = repository.get_sync(sync_id)
    if sync is None:
        raise HTTPException(
            status_code=404, detail={"error": "sync_not_found", "detail": f"no sync with id '{sync_id}'"}
        )
    return _sync_response(sync)
