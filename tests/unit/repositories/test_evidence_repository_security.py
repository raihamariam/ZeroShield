"""Security test (SRS §11.1): saved evidence must always stay under the repository root."""

from pathlib import Path

from zeroshield.models import ExperimentDefinition, ExperimentMetrics, PolicyDecision
from zeroshield.repositories import LocalEvidenceRepository, build_run_evidence
from zeroshield.runners import RunOutcome


def test_local_evidence_repository_writes_always_stay_under_root(
    tmp_path: Path,
    valid_experiment_definition_data: dict,
    evidence_run_outcome: RunOutcome,
    evidence_metrics: ExperimentMetrics,
    evidence_policy_decision: PolicyDecision,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    bundle = build_run_evidence(
        experiment,
        "vpn-pre-auth-request-v1",
        evidence_run_outcome,
        evidence_metrics,
        evidence_policy_decision,
    )
    repo = LocalEvidenceRepository(tmp_path)
    run_dir = repo.save_run_evidence(bundle)

    resolved_root = tmp_path.resolve()
    resolved_run_dir = run_dir.resolve()
    assert resolved_root in resolved_run_dir.parents
