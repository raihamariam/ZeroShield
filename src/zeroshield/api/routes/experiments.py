"""Experiment listing, detail, validation, and execution routes.

Every handler here is a thin wrapper: it loads the already-validated
ExperimentDefinition via the get_experiment dependency and delegates all
safety/execution work to zeroshield.services.experiment_service. Denials
(PolicyRefusalError) and unrunnable-experiment errors (ExperimentServiceError)
are handled centrally in zeroshield.api.errors and are never caught here.
"""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends

from zeroshield.api.dependencies import get_experiment, get_experiments_dir, get_results_root
from zeroshield.api.schemas import (
    CVESummary,
    ExecutionContextRequest,
    ExperimentDetailResponse,
    ExperimentListResponse,
    ExperimentSummary,
    KeyMetrics,
    RunResponse,
    ValidationResponse,
)
from zeroshield.models import ExperimentDefinition
from zeroshield.services import experiment_service

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
    response_model=RunResponse,
    summary="Run an experiment",
    description="Executes baseline and mitigation synchronously via the existing orchestration "
    "layer and persists evidence. Denied by SafetyPolicy -> 403. Unrunnable (missing dataset, "
    "unknown strategy) -> 422.",
)
def run_experiment(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    results_root: Annotated[Path, Depends(get_results_root)],
    request: ExecutionContextRequest,
) -> RunResponse:
    summary = experiment_service.run_experiment(
        experiment, execution_context=request.execution_context, results_root=results_root
    )
    baseline_metrics = summary.comparison_report.baseline_metrics
    mitigation_metrics = summary.comparison_report.mitigation_metrics
    return RunResponse(
        experiment_id=experiment.experiment_id,
        baseline_run_id=summary.comparison_report.baseline_run_id,
        mitigation_run_id=summary.comparison_report.mitigation_run_id,
        status="completed",
        safety_passed=True,
        total_cases=summary.comparison_report.total_cases,
        key_metrics=KeyMetrics(
            baseline_block_rate=baseline_metrics.block_rate,
            mitigation_block_rate=mitigation_metrics.block_rate,
            baseline_valid_acceptance_rate=baseline_metrics.valid_acceptance_rate,
            mitigation_valid_acceptance_rate=mitigation_metrics.valid_acceptance_rate,
            block_rate_improvement=summary.comparison_report.block_rate_improvement,
        ),
        evidence_location=str(summary.results_dir),
    )
