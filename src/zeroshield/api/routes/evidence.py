"""Read-only results/evidence routes.

Both routes reuse experiment_service.load_latest_evidence, which reads only
already-persisted evidence through the existing LocalEvidenceRepository and
each manifest's own artefact_paths. No dataset/experiment path is ever
accepted from the client - only experiment_id (resolved via get_experiment,
see zeroshield.api.dependencies), so there is no arbitrary filesystem access
here.
"""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from zeroshield.api.dependencies import get_experiment, get_results_root
from zeroshield.api.schemas import (
    EvidenceResponse,
    MetricsSummary,
    ResultsResponse,
    RunEvidenceSummary,
)
from zeroshield.models import EvidenceManifest, ExperimentDefinition
from zeroshield.repositories import verify_manifest_integrity
from zeroshield.services import experiment_service
from zeroshield.services.experiment_service import EvidenceView

router = APIRouter(tags=["evidence"])


def _load_view(experiment: ExperimentDefinition, results_root: Path) -> EvidenceView:
    view = experiment_service.load_latest_evidence(experiment.experiment_id, results_root)
    if view is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "evidence_not_found",
                "detail": f"no results have been generated yet for '{experiment.experiment_id}'",
            },
        )
    return view


@router.get(
    "/experiments/{experiment_id}/results",
    response_model=ResultsResponse,
    summary="Get latest results",
    description="Returns the most recently generated baseline-vs-mitigation comparison for this "
    "experiment. 404 if it has never been run.",
)
def get_results(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    results_root: Annotated[Path, Depends(get_results_root)],
) -> ResultsResponse:
    view = _load_view(experiment, results_root)
    comparison = view.comparison
    excluded = {"run_id", "calculated_at", "calculation_version"}
    return ResultsResponse(
        experiment_id=comparison.experiment_id,
        baseline_run_id=comparison.baseline_run_id,
        mitigation_run_id=comparison.mitigation_run_id,
        total_cases=comparison.total_cases,
        baseline_metrics=MetricsSummary(**comparison.baseline_metrics.model_dump(exclude=excluded)),
        mitigation_metrics=MetricsSummary(**comparison.mitigation_metrics.model_dump(exclude=excluded)),
        block_rate_improvement=comparison.block_rate_improvement,
        latency_overhead_ms=comparison.latency_overhead_ms,
        limitations=comparison.limitations,
    )


def _manifest_summary(manifest: EvidenceManifest) -> RunEvidenceSummary:
    return RunEvidenceSummary(
        run_id=manifest.run_id,
        mode=manifest.mode.value,
        strategy_id=manifest.strategy_id,
        started_at=manifest.started_at.isoformat(),
        completed_at=manifest.completed_at.isoformat(),
        dataset_id=manifest.test_set_id,
        dataset_sha256=manifest.test_set_sha256,
        git_commit=manifest.git_commit,
        manifest_sha256=manifest.manifest_sha256,
        integrity_verified=verify_manifest_integrity(manifest),
    )


@router.get(
    "/experiments/{experiment_id}/evidence",
    response_model=EvidenceResponse,
    summary="Get evidence metadata",
    description="Returns factual evidence metadata (manifest hashes, integrity, dataset identity) "
    "for the latest run. Read-only; does not expose arbitrary filesystem paths. 404 if never run.",
)
def get_evidence(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    results_root: Annotated[Path, Depends(get_results_root)],
) -> EvidenceResponse:
    view = _load_view(experiment, results_root)
    return EvidenceResponse(
        experiment_id=view.experiment_id,
        evidence_location=str(view.results_dir),
        baseline=_manifest_summary(view.baseline_manifest),
        mitigation=_manifest_summary(view.mitigation_manifest),
    )
