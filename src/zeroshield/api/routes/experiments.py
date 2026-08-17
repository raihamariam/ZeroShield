"""Experiment listing, detail, validation, and (asynchronous) execution routes.

Every handler here is a thin wrapper: it loads the already-validated
ExperimentDefinition via the get_experiment dependency and delegates all
safety/execution work to zeroshield.services.experiment_service - except
/runs, which only queues a job. SafetyPolicy is evaluated solely by the
RabbitMQ worker (zeroshield.worker.processor) when that job actually runs,
never here.
"""

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends

from zeroshield.api.dependencies import (
    CurrentUser,
    get_audit_repository,
    get_experiment,
    get_experiments_dir,
    get_job_store,
    get_publisher,
    get_request_id,
    get_run_repository,
    require_role,
)
from zeroshield.api.schemas import (
    CVESummary,
    ExecutionContextRequest,
    ExperimentDetailResponse,
    ExperimentListResponse,
    ExperimentSummary,
    JobSubmittedResponse,
    ValidationResponse,
)
from zeroshield.audit.models import Action
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role, User
from zeroshield.models import ExperimentDefinition
from zeroshield.models.enums import RunEventType
from zeroshield.observability.metrics import EXPERIMENT_RUNS_SUBMITTED_TOTAL
from zeroshield.repositories import RunRepository
from zeroshield.services import experiment_service
from zeroshield.services.job_store import JobRecord, JobStatus, JobStore, RunJobMessage

logger = logging.getLogger("zeroshield.api")

router = APIRouter(tags=["experiments"])


@router.get(
    "/experiments",
    response_model=ExperimentListResponse,
    summary="List discovered experiments",
    description="Discovers valid ExperimentDefinition files under the experiments directory. "
    "Never hard-coded to any specific experiment ID.",
)
def list_experiments(
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
    _current_user: CurrentUser,
) -> ExperimentListResponse:
    discovery = experiment_service.list_experiments(experiments_dir)
    return ExperimentListResponse(
        experiments=[
            ExperimentSummary(
                experiment_id=e.experiment_id,
                title=e.title,
                domain=e.domain.value,
                safety_level=e.safety_level.value,
                approval_status=e.approval_status.value,
            )
            for e in discovery.experiments
        ]
    )


@router.get(
    "/experiments/{experiment_id}",
    response_model=ExperimentDetailResponse,
    summary="Get experiment details",
    description="Returns the full ExperimentDefinition for one experiment. 404 if unknown.",
)
def get_experiment_detail(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    _current_user: CurrentUser,
) -> ExperimentDetailResponse:
    return ExperimentDetailResponse(
        experiment_id=experiment.experiment_id,
        title=experiment.title,
        domain=experiment.domain.value,
        description=experiment.description,
        related_cves=[
            CVESummary(cve_id=c.cve_id, cvss_score=c.cvss_score, cisa_kev=c.cisa_kev)
            for c in experiment.related_cves
        ],
        failure_pattern=experiment.failure_pattern,
        root_cause=experiment.root_cause.value,
        vendor_mitigation=experiment.vendor_mitigation,
        mitigation_gap=experiment.mitigation_gap,
        research_question=experiment.research_question,
        hypothesis=experiment.hypothesis,
        safety_level=experiment.safety_level.value,
        approval_status=experiment.approval_status.value,
        baseline_strategy=experiment.baseline_strategy,
        mitigation_strategy=experiment.mitigation_strategy,
    )


@router.post(
    "/experiments/{experiment_id}/validate",
    response_model=ValidationResponse,
    summary="Validate an experiment",
    description="Runs schema, dataset, and SafetyPolicy checks for the given execution context. "
    "Never executes the experiment.",
)
def validate_experiment(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    request: ExecutionContextRequest,
    _current_user: CurrentUser,
) -> ValidationResponse:
    dataset_path = Path.cwd() / experiment.dataset_path
    dataset_available = dataset_path.is_file()
    check = experiment_service.check_safety(experiment, execution_context=request.execution_context)
    return ValidationResponse(
        experiment_id=experiment.experiment_id,
        execution_context=request.execution_context.value,
        dataset_available=dataset_available,
        safety_passed=check.decision.allowed,
        safety_reasons=check.decision.reasons,
        overall_valid=dataset_available and check.decision.allowed,
    )


@router.post(
    "/experiments/{experiment_id}/runs",
    response_model=JobSubmittedResponse,
    status_code=202,
    summary="Submit an experiment run (asynchronous)",
    description="Queues baseline+mitigation execution on RabbitMQ and returns immediately with "
    "a job_id. Poll GET /jobs/{job_id} for status and, once completed, the result. SafetyPolicy "
    "is evaluated by the worker when the job actually runs - it is never evaluated or bypassed "
    "here, so a 202 response is not itself proof the run was, or will be, allowed.",
)
def submit_run(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    request: ExecutionContextRequest,
    job_store: Annotated[JobStore, Depends(get_job_store)],
    publish: Annotated[Callable[[RunJobMessage], None], Depends(get_publisher)],
    run_repository: Annotated[RunRepository, Depends(get_run_repository)],
    audit_repository: Annotated[AuditRepository, Depends(get_audit_repository)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    current_user: Annotated[User, Depends(require_role(Role.RESEARCHER, Role.REVIEWER, Role.ADMIN))],
) -> JobSubmittedResponse:
    job_id = f"JOB-{uuid.uuid4().hex}"
    now = datetime.now(UTC)
    job_store.save(
        JobRecord(
            job_id=job_id,
            experiment_id=experiment.experiment_id,
            execution_context=request.execution_context,
            status=JobStatus.QUEUED,
            submitted_at=now,
            updated_at=now,
        )
    )
    publish(
        RunJobMessage(
            job_id=job_id,
            experiment_id=experiment.experiment_id,
            execution_context=request.execution_context,
            submitted_by_user_id=current_user.user_id,
            submitted_by_username=current_user.username,
        )
    )
    EXPERIMENT_RUNS_SUBMITTED_TOTAL.labels(
        experiment_id=experiment.experiment_id, execution_context=request.execution_context.value
    ).inc()
    # Best-effort: the rich RunEvent trail is auxiliary observability, never
    # a safety authority or a precondition for the job itself - a Postgres
    # hiccup here must never prevent a valid job from being queued.
    try:
        run_repository.record_event(
            job_id,
            experiment.experiment_id,
            RunEventType.QUEUED,
            execution_context=request.execution_context.value,
        )
    except Exception:
        logger.warning("failed to record QUEUED run event for job %s", job_id, exc_info=True)
    audit_repository.record(
        actor_user_id=current_user.user_id, actor_username=current_user.username, actor_role=current_user.role.value,
        action=Action.RUN_SUBMITTED, target_type="job", target_id=job_id, request_id=request_id,
        metadata={"experiment_id": experiment.experiment_id, "execution_context": request.execution_context.value},
    )
    return JobSubmittedResponse(
        job_id=job_id, experiment_id=experiment.experiment_id, status=JobStatus.QUEUED.value
    )
