from datetime import UTC, datetime

import pytest

from zeroshield.models import (
    ApprovalStatus,
    ExperimentDefinition,
    ExperimentMetrics,
    ExperimentRun,
    PolicyDecision,
)
from zeroshield.repositories import build_run_evidence, verify_manifest_integrity
from zeroshield.runners import RunOutcome

STARTED = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)


def test_build_run_evidence_produces_valid_manifest(
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

    assert bundle.manifest.run_id == "RUN-001"
    assert bundle.manifest.experiment_id == "ZC-VPN-EXP-999"
    assert bundle.manifest.strategy_id == "weak_schema_length_baseline"
    assert bundle.manifest.review_status == ApprovalStatus.DRAFT
    assert set(bundle.artefacts) == {
        "experiment.json",
        "dataset_manifest.json",
        "results.json",
        "metrics.json",
        "manifest.json",
    }


def test_build_run_evidence_artefact_paths_are_relative(
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
    for path in bundle.manifest.artefact_paths.values():
        assert not path.is_absolute()


def test_manifest_integrity_verifies_for_freshly_built_manifest(
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
    assert verify_manifest_integrity(bundle.manifest) is True


def test_manifest_integrity_fails_after_tampering(
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
    tampered = bundle.manifest.model_copy(update={"strategy_id": "different_strategy_id"})
    assert verify_manifest_integrity(tampered) is False


def test_build_run_evidence_rejects_incomplete_run(
    valid_experiment_definition_data: dict,
    evidence_metrics: ExperimentMetrics,
    evidence_policy_decision: PolicyDecision,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    run = ExperimentRun(
        run_id="RUN-001",
        experiment_id="ZC-VPN-EXP-999",
        mode="baseline",
        dataset_hash="a" * 64,
        git_commit="abc1234",
        environment={"python_version": "3.12.10"},
        started_at=STARTED,
        status="pending",
    )
    incomplete_outcome = RunOutcome(
        run=run, strategy_id="weak_schema_length_baseline", case_results=[]
    )
    with pytest.raises(ValueError, match="has not completed"):
        build_run_evidence(
            experiment,
            "vpn-pre-auth-request-v1",
            incomplete_outcome,
            evidence_metrics,
            evidence_policy_decision,
        )
