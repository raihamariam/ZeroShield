import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from zeroshield.models import (
    EvidenceManifest,
    ExperimentDefinition,
    ExperimentMetrics,
    PolicyDecision,
)
from zeroshield.runners import RunOutcome


@dataclass(frozen=True)
class EvidenceBundle:
    manifest: EvidenceManifest
    artefacts: dict[str, bytes]


def _canonical_json_bytes(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def build_run_evidence(
    experiment: ExperimentDefinition,
    test_set_id: str,
    run_outcome: RunOutcome,
    metrics: ExperimentMetrics,
    safety_decision: PolicyDecision,
    *,
    manifest_version: str = "1.0.0",
) -> EvidenceBundle:
    """Build one run's EvidenceManifest and artefact bytes (no I/O), per FR-010 and §15.2."""
    run = run_outcome.run
    completed_at = run.completed_at
    if completed_at is None:
        raise ValueError("cannot build evidence for a run that has not completed")

    artefact_paths = {
        "experiment": Path("experiment.json"),
        "dataset_manifest": Path("dataset_manifest.json"),
        "results": Path("results.json"),
        "metrics": Path("metrics.json"),
    }

    def _manifest(manifest_sha256: str) -> EvidenceManifest:
        return EvidenceManifest(
            manifest_version=manifest_version,
            experiment_id=experiment.experiment_id,
            experiment_version=experiment.version,
            run_id=run.run_id,
            mode=run.mode,
            test_set_id=test_set_id,
            test_set_sha256=run.dataset_hash,
            git_commit=run.git_commit,
            container_image_digest=None,
            started_at=run.started_at,
            completed_at=completed_at,
            strategy_id=run_outcome.strategy_id,
            metrics=metrics,
            artefact_paths=artefact_paths,
            safety_decision=safety_decision,
            review_status=experiment.approval_status,
            manifest_sha256=manifest_sha256,
        )

    unhashed = _manifest("0" * 64)
    hashable = unhashed.model_dump(mode="json", exclude={"manifest_sha256"})
    manifest_sha256 = hashlib.sha256(_canonical_json_bytes(hashable)).hexdigest()
    manifest = _manifest(manifest_sha256)

    dataset_manifest_payload = {"dataset_path": str(experiment.dataset_path), "sha256": run.dataset_hash}
    results_payload = [r.model_dump(mode="json") for r in run_outcome.case_results]

    artefacts = {
        "experiment.json": experiment.model_dump_json(indent=2).encode("utf-8"),
        "dataset_manifest.json": json.dumps(dataset_manifest_payload, indent=2).encode("utf-8"),
        "results.json": json.dumps(results_payload, indent=2).encode("utf-8"),
        "metrics.json": metrics.model_dump_json(indent=2).encode("utf-8"),
        "manifest.json": manifest.model_dump_json(indent=2).encode("utf-8"),
    }
    return EvidenceBundle(manifest=manifest, artefacts=artefacts)


def verify_manifest_integrity(manifest: EvidenceManifest) -> bool:
    """Recompute manifest_sha256 the same way build_run_evidence did, per AC-08."""
    hashable = manifest.model_dump(mode="json", exclude={"manifest_sha256"})
    recomputed = hashlib.sha256(_canonical_json_bytes(hashable)).hexdigest()
    return recomputed == manifest.manifest_sha256
