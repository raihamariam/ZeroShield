"""Read-only polling route for async run jobs submitted via POST /experiments/{id}/runs.

job_id is server-generated (JOB-<uuid4 hex>) and, unlike experiment_id, is used
directly to build a filesystem path inside JobStore. The pattern constraint
below rejects any other shape (including path-traversal attempts) before the
route body or JobStore ever sees it.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Path as FastAPIPath

from zeroshield.api.dependencies import get_job_store
from zeroshield.api.schemas import JobResultSummary, JobStatusResponse
from zeroshield.services.job_store import JobStore

router = APIRouter(tags=["jobs"])

_JOB_ID_PATTERN = r"^JOB-[0-9a-f]{32}$"


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
