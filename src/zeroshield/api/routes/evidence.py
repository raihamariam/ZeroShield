"""Read-only results/evidence routes.

Both routes reuse experiment_service.load_latest_evidence, which reads only
already-persisted evidence through the existing LocalEvidenceRepository and
each manifest's own artefact_paths. No dataset/experiment path is ever
accepted from the client - only experiment_id (resolved via get_experiment,
see zeroshield.api.dependencies), so there is no arbitrary filesystem access
here.
"""

import io
import zipfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from zeroshield.api.dependencies import (
    CurrentUser,
    get_audit_repository,
    get_experiment,
    get_request_id,
    get_results_root,
)
from zeroshield.api.schemas import (
    EvidenceResponse,
    MetricsSummary,
    ResultsResponse,
    RunEvidenceSummary,
)
from zeroshield.audit.models import Action
from zeroshield.audit.repository import AuditRepository
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
    _current_user: CurrentUser,
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
    _current_user: CurrentUser,
) -> EvidenceResponse:
    view = _load_view(experiment, results_root)
    return EvidenceResponse(
        experiment_id=view.experiment_id,
        evidence_location=str(view.results_dir),
        baseline=_manifest_summary(view.baseline_manifest),
        mitigation=_manifest_summary(view.mitigation_manifest),
    )


@router.get(
    "/experiments/{experiment_id}/evidence/bundle",
    summary="Download the evidence bundle for the latest run (zip)",
    description="Streams a zip of comparison.json plus both baseline and mitigation run "
    "directories (manifest.json and artefacts) - exactly the files already summarised by "
    "GET .../evidence, nothing more. Run directories come from the already-loaded, trusted "
    "EvidenceManifest records (never a client-supplied path), so this cannot be used for "
    "arbitrary filesystem access. Never exposes MinIO admin credentials - evidence is read "
    "through the same local results_root every other evidence route uses. 404 if never run.",
)
def download_evidence_bundle(
    experiment: Annotated[ExperimentDefinition, Depends(get_experiment)],
    results_root: Annotated[Path, Depends(get_results_root)],
    audit_repository: Annotated[AuditRepository, Depends(get_audit_repository)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    current_user: CurrentUser,
) -> StreamingResponse:
    view = _load_view(experiment, results_root)
    experiment_dir = results_root / experiment.experiment_id
    audit_repository.record(
        actor_user_id=current_user.user_id, actor_username=current_user.username, actor_role=current_user.role.value,
        action=Action.EVIDENCE_VERIFIED, target_type="experiment", target_id=experiment.experiment_id,
        request_id=request_id,
        metadata={"baseline_run_id": view.baseline_manifest.run_id, "mitigation_run_id": view.mitigation_manifest.run_id},
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        comparison_path = experiment_dir / "comparison.json"
        if comparison_path.is_file():
            zf.write(comparison_path, arcname="comparison.json")
        for manifest in (view.baseline_manifest, view.mitigation_manifest):
            run_dir = experiment_dir / manifest.run_id
            if not run_dir.is_dir():
                continue
            for artefact_path in sorted(run_dir.iterdir()):
                if artefact_path.is_file():
                    zf.write(artefact_path, arcname=f"{manifest.run_id}/{artefact_path.name}")
    buffer.seek(0)

    filename = f"{experiment.experiment_id}-evidence.zip"
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
