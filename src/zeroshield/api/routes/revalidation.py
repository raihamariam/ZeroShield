"""Revalidation candidate routes (V2 Phase 5, Step 11).

POST /revalidation/scan runs the deterministic trigger scan and creates
candidates - it never executes a run. POST .../approve only flips a
candidate's status to "approved"; the actual run is submitted afterwards
through the ordinary POST /experiments/{id}/runs or
POST /experiment-versions/{id}/runs path, exactly like any other run - see
zeroshield.assurance.models.RevalidationCandidate's docstring for why this
split is load-bearing, not incidental.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from zeroshield.api.dependencies import (
    get_assurance_repository,
    get_experiments_dir,
    get_vulnerability_repository,
)
from zeroshield.api.schemas import (
    CreateRevalidationCandidateRequest,
    RevalidationCandidateListResponse,
    RevalidationCandidateResponse,
    RevalidationDecisionRequest,
    RevalidationScanResponse,
)
from zeroshield.assurance.models import RevalidationCandidate
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.intelligence.repository import VulnerabilityRepository

router = APIRouter(tags=["revalidation"])


def _response(c: RevalidationCandidate) -> RevalidationCandidateResponse:
    return RevalidationCandidateResponse(
        candidate_id=c.candidate_id, control_id=c.control_id, experiment_id=c.experiment_id,
        trigger_type=c.trigger_type, trigger_detail=c.trigger_detail, status=c.status,
        created_at=c.created_at.isoformat(), reviewed_by=c.reviewed_by,
        reviewed_at=c.reviewed_at.isoformat() if c.reviewed_at else None, review_note=c.review_note,
    )


@router.post(
    "/revalidation/scan",
    response_model=RevalidationScanResponse,
    summary="Scan for revalidation triggers and create candidates",
    description="Deterministic (V2 Phase 5, Step 11) - detects KEV-state changes, material EPSS "
    "changes, unvalidated new control versions, and staleness against already-recorded state. "
    "Never auto-executes anything; only creates pending RevalidationCandidate rows a human then "
    "reviews.",
)
def scan_for_revalidation(
    assurance_repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    vuln_repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
) -> RevalidationScanResponse:
    from zeroshield.assurance.revalidation import scan

    summary = scan(assurance_repository, vuln_repository, experiments_dir)
    return RevalidationScanResponse(
        candidates_created=[_response(c) for c in summary.candidates_created],
        controls_scanned=summary.controls_scanned,
    )


@router.get("/revalidation", response_model=RevalidationCandidateListResponse, summary="List revalidation candidates")
def list_revalidation_candidates(
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)], status: str | None = None
) -> RevalidationCandidateListResponse:
    return RevalidationCandidateListResponse(candidates=[_response(c) for c in repository.list_candidates(status=status)])


@router.post(
    "/revalidation",
    response_model=RevalidationCandidateResponse,
    status_code=201,
    summary="Manually raise a revalidation candidate",
    description="For trigger types the automated scan does not detect (new_related_cve, "
    "advisory_update) - an analyst reviewing a correlation result or a vendor advisory can "
    "raise one directly.",
)
def create_revalidation_candidate(
    request: CreateRevalidationCandidateRequest,
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
) -> RevalidationCandidateResponse:
    if repository.get_control(request.control_id) is None:
        raise HTTPException(
            status_code=404, detail={"error": "control_not_found", "detail": f"no control '{request.control_id}'"}
        )
    candidate = repository.create_candidate(
        RevalidationCandidate(
            candidate_id=f"REVAL-{uuid.uuid4().hex}", control_id=request.control_id,
            experiment_id=request.experiment_id, trigger_type=request.trigger_type,
            trigger_detail=request.trigger_detail, status="pending", created_at=datetime.now(UTC),
        )
    )
    return _response(candidate)


@router.get("/revalidation/{candidate_id}", response_model=RevalidationCandidateResponse, summary="Get one revalidation candidate")
def get_revalidation_candidate(
    candidate_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]
) -> RevalidationCandidateResponse:
    candidate = repository.get_candidate(candidate_id)
    if candidate is None:
        raise HTTPException(
            status_code=404, detail={"error": "candidate_not_found", "detail": f"no candidate '{candidate_id}'"}
        )
    return _response(candidate)


def _transition(
    candidate_id: str, status: str, request: RevalidationDecisionRequest, repository: AssuranceRepository
) -> RevalidationCandidateResponse:
    existing = repository.get_candidate(candidate_id)
    if existing is None:
        raise HTTPException(
            status_code=404, detail={"error": "candidate_not_found", "detail": f"no candidate '{candidate_id}'"}
        )
    if existing.status != "pending":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "candidate_not_pending",
                "detail": f"candidate '{candidate_id}' is '{existing.status}', not 'pending'",
            },
        )
    updated = repository.update_candidate_status(
        candidate_id, status=status, reviewed_by=request.actor, review_note=request.note
    )
    assert updated is not None
    return _response(updated)


@router.post(
    "/revalidation/{candidate_id}/approve",
    response_model=RevalidationCandidateResponse,
    summary="Approve a revalidation candidate",
    description="Only marks the candidate approved - submit the actual run afterwards through "
    "POST /experiments/{id}/runs or POST /experiment-versions/{id}/runs, same as any other run. "
    "Never itself queues or executes anything.",
)
def approve_revalidation_candidate(
    candidate_id: str,
    request: RevalidationDecisionRequest,
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
) -> RevalidationCandidateResponse:
    return _transition(candidate_id, "approved", request, repository)


@router.post(
    "/revalidation/{candidate_id}/dismiss", response_model=RevalidationCandidateResponse, summary="Dismiss a revalidation candidate"
)
def dismiss_revalidation_candidate(
    candidate_id: str,
    request: RevalidationDecisionRequest,
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
) -> RevalidationCandidateResponse:
    return _transition(candidate_id, "dismissed", request, repository)
