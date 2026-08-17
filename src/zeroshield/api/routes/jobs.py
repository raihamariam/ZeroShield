"""Read-only polling/listing/streaming routes for async run jobs submitted via
POST /experiments/{id}/runs or POST /experiment-versions/{id}/runs.

job_id is server-generated (JOB-<uuid4 hex>) and, unlike experiment_id, is used
directly to build a filesystem path inside JobStore. The pattern constraint
below rejects any other shape (including path-traversal attempts) before the
route body or JobStore ever sees it.

GET /jobs/{job_id}/events (V2 Phase 4, Step 7) streams the *real* RunEvent
history from RunRepository (Postgres-backed since Phase 1) as Server-Sent
Events - never a fabricated progress percentage. If DATABASE_URL is not
configured, RunRepository is the no-op NullRunRepository (Phase 1's existing
fallback), so the stream degrades honestly to just the coarse JobStore status
transitions instead of the rich per-stage trail - still real data, never
invented detail.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Path as FastAPIPath
from fastapi.responses import StreamingResponse

from zeroshield.api.dependencies import get_job_store, get_run_repository
from zeroshield.api.schemas import JobListResponse, JobResultSummary, JobStatusResponse
from zeroshield.repositories import RunRepository
from zeroshield.services.job_store import JobRecord, JobStatus, JobStore

router = APIRouter(tags=["jobs"])

_JOB_ID_PATTERN = r"^JOB-[0-9a-f]{32}$"
_TERMINAL_STATUSES = frozenset({JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.DENIED})
_POLL_INTERVAL_SECONDS = 1.0
_MAX_STREAM_SECONDS = 300.0  # safety cap so a client that never disconnects can't hold the connection forever


def _job_response(record: JobRecord) -> JobStatusResponse:
    result = None
    if record.result is not None:
        result = JobResultSummary(
            baseline_run_id=record.result.baseline_run_id,
            mitigation_run_id=record.result.mitigation_run_id,
            total_cases=record.result.total_cases,
            baseline_block_rate=record.result.baseline_block_rate,
            mitigation_block_rate=record.result.mitigation_block_rate,
            block_rate_improvement=record.result.block_rate_improvement,
            evidence_location=record.result.evidence_location,
        )
    return JobStatusResponse(
        job_id=record.job_id,
        experiment_id=record.experiment_id,
        execution_context=record.execution_context.value,
        status=record.status.value,
        submitted_at=record.submitted_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        result=result,
        error=record.error,
    )


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Get an async run job's status/result",
    description="Poll this after POST /experiments/{experiment_id}/runs. Status is one of "
    "queued, running, completed, failed, denied. 404 if the job_id is unknown.",
)
def get_job(
    job_id: Annotated[str, FastAPIPath(pattern=_JOB_ID_PATTERN)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
) -> JobStatusResponse:
    record = job_store.load(job_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "job_not_found", "detail": f"no job with id '{job_id}'"},
        )
    return _job_response(record)


@router.get(
    "/jobs",
    response_model=JobListResponse,
    summary="List recent run jobs",
    description="Powers Mission Control/Runs list views (V2 Phase 4) - most-recently-submitted "
    "first, optionally filtered by status.",
)
def list_jobs(
    job_store: Annotated[JobStore, Depends(get_job_store)],
    status: str | None = None,
    limit: int = 50,
) -> JobListResponse:
    records = job_store.list_all()
    if status is not None:
        records = [r for r in records if r.status.value == status]
    return JobListResponse(jobs=[_job_response(r) for r in records[: max(1, min(limit, 200))]])


@router.get(
    "/jobs/{job_id}/events",
    summary="Stream a run job's real lifecycle events (Server-Sent Events)",
    description="text/event-stream of the actual RunEvent history (QUEUED/PREPARING/SAFETY_CHECK/"
    "RUNNING_BASELINE/RUNNING_MITIGATION/ANALYSING/GENERATING_EVIDENCE/COMPLETED, or DENIED/FAILED) "
    "as recorded by the worker - never a fabricated progress percentage. Closes automatically once "
    "the job reaches a terminal status. If DATABASE_URL is not configured, degrades honestly to the "
    "coarser JobStore status alone (no rich per-stage trail exists to stream).",
)
async def stream_job_events(
    job_id: Annotated[str, FastAPIPath(pattern=_JOB_ID_PATTERN)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
    run_repository: Annotated[RunRepository, Depends(get_run_repository)],
) -> StreamingResponse:
    record = job_store.load(job_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "job_not_found", "detail": f"no job with id '{job_id}'"},
        )

    async def _generate() -> AsyncIterator[str]:
        seen = 0
        elapsed = 0.0
        while elapsed < _MAX_STREAM_SECONDS:
            events = run_repository.list_events(job_id)
            for event in events[seen:]:
                payload = {
                    "event_type": event.event_type.value,
                    "occurred_at": event.occurred_at.isoformat(),
                    "detail": event.detail,
                }
                yield f"event: run_event\ndata: {json.dumps(payload)}\n\n"
            seen = len(events)

            current = job_store.load(job_id)
            if current is not None and current.status in _TERMINAL_STATUSES:
                final_payload = {"job_status": current.status.value, "error": current.error}
                yield f"event: job_terminal\ndata: {json.dumps(final_payload)}\n\n"
                return

            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            elapsed += _POLL_INTERVAL_SECONDS

        yield 'event: stream_timeout\ndata: {"detail": "stream exceeded maximum duration; poll GET /jobs/{job_id} instead"}\n\n'

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
