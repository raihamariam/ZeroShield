"""Domain Pack / Validation Template / Dataset Generator / Experiment Studio /
Verdict routes (V2 Phase 3, Step 8). Every handler is a thin wrapper over
zeroshield.domain_packs/templates/generators/studio/verdict - no workflow or
validation rule is duplicated here.
"""

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ValidationError

from zeroshield.api.dependencies import (
    get_experiment,
    get_experiment_version_repository,
    get_experiments_dir,
    get_job_store,
    get_publisher,
    get_results_root,
)
from zeroshield.api.schemas import (
    ApprovalActionRequest,
    ApprovalDecisionResponse,
    CreateExperimentVersionRequest,
    DomainPackListResponse,
    DomainPackResponse,
    EditExperimentVersionRequest,
    ExperimentVersionListResponse,
    ExperimentVersionResponse,
    GenerateDatasetRequest,
    GenerateDatasetResponse,
    JobSubmittedResponse,
    ValidationTemplateListResponse,
    ValidationTemplateResponse,
    VerdictResponse,
)
from zeroshield.domain_packs import UnknownDomainPackError, known_domain_packs, resolve_domain_pack
from zeroshield.generators import (
    UnknownGeneratorError,
    resolve_generator,
    resolve_generator_config_cls,
)
from zeroshield.models import CVEReference, ExperimentDefinition
from zeroshield.models.enums import ExperimentVersionStatus
from zeroshield.services import experiment_service
from zeroshield.services.job_store import JobRecord, JobStatus, JobStore, RunJobMessage
from zeroshield.studio import (
    ExperimentBuilderError,
    ImmutableVersionError,
    InvalidTransitionError,
    build_experiment_draft,
    edit_draft,
    materialise_to_experiments_dir,
    transition,
)
from zeroshield.studio.repository import ExperimentVersionRepository
from zeroshield.templates import UnknownTemplateError, list_templates, resolve_template
from zeroshield.verdict import compute_verdict

router = APIRouter(tags=["studio"])
logger = logging.getLogger("zeroshield.api")


def _domain_pack_response(pack: object) -> DomainPackResponse:
    return DomainPackResponse(
        pack_id=pack.pack_id, name=pack.name, version=pack.version, domain=pack.domain.value,  # type: ignore[attr-defined]
        supported_failure_patterns=pack.supported_failure_patterns, template_ids=pack.template_ids,  # type: ignore[attr-defined]
        allowed_strategy_ids=sorted(pack.allowed_strategy_ids), dataset_generator_id=pack.dataset_generator_id,  # type: ignore[attr-defined]
        domain_metrics=[m.value for m in pack.domain_metrics], compatibility=pack.compatibility,  # type: ignore[attr-defined]
    )


def _template_response(t: object) -> ValidationTemplateResponse:
    return ValidationTemplateResponse(
        template_id=t.template_id, version=t.version, domain_pack_id=t.domain_pack_id, name=t.name,  # type: ignore[attr-defined]
        supported_failure_patterns=t.supported_failure_patterns, required_input_fields=t.required_input_fields,  # type: ignore[attr-defined]
        allowed_baseline_strategies=t.allowed_baseline_strategies,  # type: ignore[attr-defined]
        allowed_mitigation_strategies=t.allowed_mitigation_strategies,  # type: ignore[attr-defined]
        configurable_parameters=t.configurable_parameters, metrics_to_collect=[m.value for m in t.metrics_to_collect],  # type: ignore[attr-defined]
        safety_level=t.safety_level.value,  # type: ignore[attr-defined]
    )


def _version_response(v: object) -> ExperimentVersionResponse:
    return ExperimentVersionResponse(
        version_id=v.version_id, experiment_id=v.experiment_id, version_number=v.version_number,  # type: ignore[attr-defined]
        status=v.status.value, domain_pack_id=v.domain_pack_id, template_id=v.template_id,  # type: ignore[attr-defined]
        template_version=v.template_version, created_by=v.created_by,  # type: ignore[attr-defined]
        created_at=v.created_at.isoformat(), updated_at=v.updated_at.isoformat(),  # type: ignore[attr-defined]
    )


@router.get("/domain-packs", response_model=DomainPackListResponse, summary="List registered domain packs")
def list_domain_packs() -> DomainPackListResponse:
    return DomainPackListResponse(domain_packs=[_domain_pack_response(p) for p in known_domain_packs()])


@router.get(
    "/domain-packs/{pack_id}/templates",
    response_model=ValidationTemplateListResponse,
    summary="List a domain pack's validation templates",
)
def list_domain_pack_templates(pack_id: str) -> ValidationTemplateListResponse:
    try:
        resolve_domain_pack(pack_id)
    except UnknownDomainPackError:
        raise HTTPException(
            status_code=404, detail={"error": "domain_pack_not_found", "detail": f"no domain pack '{pack_id}'"}
        ) from None
    return ValidationTemplateListResponse(templates=[_template_response(t) for t in list_templates(pack_id)])


@router.get(
    "/templates/{template_id}/{version}",
    response_model=ValidationTemplateResponse,
    summary="Get one validation template version",
    description="Historical experiments keep their original template version - every "
    "version ever registered remains resolvable here, never overwritten.",
)
def get_template(template_id: str, version: str) -> ValidationTemplateResponse:
    try:
        template = resolve_template(template_id, version)
    except UnknownTemplateError:
        raise HTTPException(
            status_code=404,
            detail={"error": "template_not_found", "detail": f"no template '{template_id}' version '{version}'"},
        ) from None
    return _template_response(template)


@router.post(
    "/datasets/generate",
    response_model=GenerateDatasetResponse,
    summary="Generate a preview synthetic dataset",
    description="Deterministic: the same domain_pack_id/seed/config always reproduces the same "
    "dataset. Preview only - does not persist a file or create an experiment version.",
)
def generate_dataset(request: GenerateDatasetRequest) -> GenerateDatasetResponse:
    try:
        pack = resolve_domain_pack(request.domain_pack_id)
    except UnknownDomainPackError:
        raise HTTPException(
            status_code=404,
            detail={"error": "domain_pack_not_found", "detail": f"no domain pack '{request.domain_pack_id}'"},
        ) from None

    try:
        config_cls = resolve_generator_config_cls(pack.dataset_generator_id)
        config = config_cls.model_validate(request.config)
    except (UnknownGeneratorError, ValidationError) as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_dataset_config", "detail": str(exc)}
        ) from None

    generator = resolve_generator(pack.dataset_generator_id)
    generated = generator.generate(seed=request.seed, config=config)
    cases_by_category: dict[str, int] = {}
    for case in generated.test_set.cases:
        cases_by_category[case.category.value] = cases_by_category.get(case.category.value, 0) + 1

    return GenerateDatasetResponse(
        generator_id=generated.provenance.generator_id,
        generator_version=generated.provenance.generator_version,
        seed=generated.provenance.seed,
        sha256=generated.provenance.sha256,
        test_set_id=generated.test_set.test_set_id,
        case_count=len(generated.test_set.cases),
        cases_by_category=cases_by_category,
    )


@router.post(
    "/experiment-versions",
    response_model=ExperimentVersionResponse,
    status_code=201,
    summary="Create a draft experiment version (Experiment Studio)",
    description="Replaces hand-authoring an experiment JSON file: assembles a real, validated "
    "ExperimentDefinition from a Domain Pack, a Validation Template, and a deterministic "
    "generated dataset. Always created in DRAFT status.",
)
def create_experiment_version(
    request: CreateExperimentVersionRequest,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
) -> ExperimentVersionResponse:
    try:
        related_cves = [CVEReference.model_validate(c.model_dump()) for c in request.related_cves]
        version_number = repository.latest_version_number(request.experiment_id) + 1
        version = build_experiment_draft(
            experiment_id=request.experiment_id,
            version_number=version_number,
            title=request.title,
            description=request.description,
            related_cves=related_cves,
            domain_pack_id=request.domain_pack_id,
            template_id=request.template_id,
            template_version=request.template_version,
            dataset_config=_parse_dataset_config(request.domain_pack_id, request.dataset_config),
            seed=request.seed,
            failure_pattern=request.failure_pattern,
            root_cause=request.root_cause,  # type: ignore[arg-type]
            vendor_mitigation=request.vendor_mitigation,
            mitigation_gap=request.mitigation_gap,
            research_question=request.research_question,
            hypothesis=request.hypothesis,
            created_by=request.created_by,
            metrics_to_collect=request.metrics_to_collect,  # type: ignore[arg-type]
        )
    except (ExperimentBuilderError, UnknownDomainPackError, UnknownTemplateError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_experiment_version", "detail": str(exc)}) from None

    repository.save_version(version)
    return _version_response(version)


def _parse_dataset_config(domain_pack_id: str, raw_config: dict) -> BaseModel:
    pack = resolve_domain_pack(domain_pack_id)
    config_cls = resolve_generator_config_cls(pack.dataset_generator_id)
    return config_cls.model_validate(raw_config)


@router.patch(
    "/experiment-versions/{version_id}",
    response_model=ExperimentVersionResponse,
    summary="Edit a draft experiment version",
    description="Only permitted while status is DRAFT - past that, create a new version instead.",
)
def edit_experiment_version(
    version_id: str,
    request: EditExperimentVersionRequest,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
) -> ExperimentVersionResponse:
    version = repository.get_version(version_id)
    if version is None:
        raise HTTPException(
            status_code=404, detail={"error": "version_not_found", "detail": f"no version '{version_id}'"}
        )
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    try:
        updated = edit_draft(version, **updates)
    except ImmutableVersionError as exc:
        raise HTTPException(status_code=409, detail={"error": "version_immutable", "detail": str(exc)}) from None
    repository.save_version(updated)
    return _version_response(updated)


@router.get(
    "/experiment-versions/{version_id}",
    response_model=ExperimentVersionResponse,
    summary="Get one experiment version",
)
def get_experiment_version(
    version_id: str, repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)]
) -> ExperimentVersionResponse:
    version = repository.get_version(version_id)
    if version is None:
        raise HTTPException(
            status_code=404, detail={"error": "version_not_found", "detail": f"no version '{version_id}'"}
        )
    return _version_response(version)


@router.get(
    "/experiment-versions",
    response_model=ExperimentVersionListResponse,
    summary="List experiment versions",
)
def list_experiment_versions(
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
    experiment_id: str | None = None,
    status: ExperimentVersionStatus | None = None,
) -> ExperimentVersionListResponse:
    versions = repository.list_versions(experiment_id=experiment_id, status=status)
    return ExperimentVersionListResponse(versions=[_version_response(v) for v in versions])


@router.get(
    "/experiment-versions/{version_id}/approvals",
    response_model=list[ApprovalDecisionResponse],
    summary="Get one experiment version's approval history",
)
def get_approval_history(
    version_id: str, repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)]
) -> list[ApprovalDecisionResponse]:
    return [
        ApprovalDecisionResponse(
            version_id=d.version_id, from_status=d.from_status.value, to_status=d.to_status.value,
            actor=d.actor, reason=d.reason, decided_at=d.decided_at.isoformat(),
        )
        for d in repository.get_approval_history(version_id)
    ]


def _do_transition(
    version_id: str,
    target: ExperimentVersionStatus,
    request: ApprovalActionRequest,
    repository: ExperimentVersionRepository,
    experiments_dir: Path | None,
) -> ExperimentVersionResponse:
    version = repository.get_version(version_id)
    if version is None:
        raise HTTPException(
            status_code=404, detail={"error": "version_not_found", "detail": f"no version '{version_id}'"}
        )
    try:
        new_version, decision = transition(version, target, actor=request.actor, reason=request.reason)
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail={"error": "invalid_transition", "detail": str(exc)}) from None

    repository.save_version(new_version)
    repository.append_approval_decision(decision)
    if target is ExperimentVersionStatus.APPROVED and experiments_dir is not None:
        materialise_to_experiments_dir(new_version, experiments_dir)
    return _version_response(new_version)


@router.post(
    "/experiment-versions/{version_id}/submit-review",
    response_model=ExperimentVersionResponse,
    summary="Submit a draft for review (DRAFT -> READY_FOR_REVIEW)",
)
def submit_review(
    version_id: str,
    request: ApprovalActionRequest,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
) -> ExperimentVersionResponse:
    return _do_transition(version_id, ExperimentVersionStatus.READY_FOR_REVIEW, request, repository, None)


@router.post(
    "/experiment-versions/{version_id}/start-review",
    response_model=ExperimentVersionResponse,
    summary="Begin review (READY_FOR_REVIEW -> UNDER_REVIEW)",
)
def start_review(
    version_id: str,
    request: ApprovalActionRequest,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
) -> ExperimentVersionResponse:
    return _do_transition(version_id, ExperimentVersionStatus.UNDER_REVIEW, request, repository, None)


@router.post(
    "/experiment-versions/{version_id}/approve",
    response_model=ExperimentVersionResponse,
    summary="Approve (UNDER_REVIEW -> APPROVED)",
    description="Does NOT bypass SafetyPolicy - only sets the workflow state and the trusted "
    "core's own approval_status in lockstep, then materialises the ExperimentDefinition into "
    "experiments/ for the existing, unchanged run infrastructure to discover. SafetyPolicy is "
    "still evaluated, independently, every time a run is actually submitted.",
)
def approve_version(
    version_id: str,
    request: ApprovalActionRequest,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
) -> ExperimentVersionResponse:
    return _do_transition(version_id, ExperimentVersionStatus.APPROVED, request, repository, experiments_dir)


@router.post(
    "/experiment-versions/{version_id}/reject",
    response_model=ExperimentVersionResponse,
    summary="Reject (UNDER_REVIEW -> REJECTED)",
)
def reject_version(
    version_id: str,
    request: ApprovalActionRequest,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
) -> ExperimentVersionResponse:
    return _do_transition(version_id, ExperimentVersionStatus.REJECTED, request, repository, None)


@router.post(
    "/experiment-versions/{version_id}/retire",
    response_model=ExperimentVersionResponse,
    summary="Retire (APPROVED -> RETIRED)",
)
def retire_version(
    version_id: str,
    request: ApprovalActionRequest,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
) -> ExperimentVersionResponse:
    return _do_transition(version_id, ExperimentVersionStatus.RETIRED, request, repository, None)


@router.post(
    "/experiment-versions/{version_id}/runs",
    response_model=JobSubmittedResponse,
    status_code=202,
    summary="Submit an approved experiment version for asynchronous execution",
    description="Only permitted once a version is APPROVED. Delegates to the exact same "
    "queue/worker/SafetyPolicy path as POST /experiments/{id}/runs - this route only ensures "
    "the version's ExperimentDefinition is materialised into experiments/ first.",
)
def submit_experiment_version_run(
    version_id: str,
    repository: Annotated[ExperimentVersionRepository, Depends(get_experiment_version_repository)],
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
    job_store: Annotated[JobStore, Depends(get_job_store)],
    publish: Annotated[Callable[[RunJobMessage], None], Depends(get_publisher)],
) -> JobSubmittedResponse:
    version = repository.get_version(version_id)
    if version is None:
        raise HTTPException(
            status_code=404, detail={"error": "version_not_found", "detail": f"no version '{version_id}'"}
        )
    if version.status is not ExperimentVersionStatus.APPROVED:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "version_not_approved",
                "detail": f"version '{version_id}' is '{version.status.value}', not 'approved'",
            },
        )
    materialise_to_experiments_dir(version, experiments_dir)

    from zeroshield.policies import ExecutionContext

    job_id = f"JOB-{uuid.uuid4().hex}"
    now = datetime.now(UTC)
    job_store.save(
        JobRecord(
            job_id=job_id, experiment_id=version.experiment_id, execution_context=ExecutionContext.EXPERIMENT_RUN,
            status=JobStatus.QUEUED, submitted_at=now, updated_at=now,
        )
    )
    publish(
        RunJobMessage(
            job_id=job_id, experiment_id=version.experiment_id, execution_context=ExecutionContext.EXPERIMENT_RUN
        )
    )
    return JobSubmittedResponse(job_id=job_id, experiment_id=version.experiment_id, status=JobStatus.QUEUED.value)


@router.get(
    "/experiments/{experiment_id}/verdict",
    response_model=VerdictResponse,
    summary="Get the deterministic verdict for an experiment's latest run",
    description="Pure, deterministic, threshold-based (Step 7) - never AI-decided. 404 until "
    "the experiment has completed at least one run.",
)
def get_experiment_verdict(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    results_root: Annotated[Path, Depends(get_results_root)],
) -> VerdictResponse:
    evidence = experiment_service.load_latest_evidence(experiment.experiment_id, results_root)
    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_evidence", "detail": f"experiment '{experiment.experiment_id}' has no completed run"},
        )
    result = compute_verdict(evidence.comparison)
    return VerdictResponse(
        experiment_id=experiment.experiment_id, label=result.label.value, reasons=result.reasons,
        thresholds_used=result.thresholds_used, failed_criteria=result.failed_criteria,
        limitations=result.limitations, generated_at=result.generated_at.isoformat(),
    )
