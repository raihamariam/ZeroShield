from datetime import UTC, datetime
from pathlib import Path

from zeroshield.models import (
    ComparisonReport,
    ExperimentDefinition,
    ExperimentMetrics,
    PolicyDecision,
)
from zeroshield.repositories import (
    LocalEvidenceRepository,
    build_run_evidence,
    verify_manifest_integrity,
)
from zeroshield.runners import RunOutcome

STARTED = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)


def test_save_and_load_run_evidence_round_trips(
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
    assert run_dir == tmp_path / "ZC-VPN-EXP-999" / "RUN-001"
    for name in bundle.artefacts:
        assert (run_dir / name).is_file()

    loaded = repo.load_manifest("ZC-VPN-EXP-999", "RUN-001")
    assert loaded == bundle.manifest
    assert verify_manifest_integrity(loaded) is True


def test_saved_manifest_detects_disk_level_tampering(
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
    repo.save_run_evidence(bundle)

    manifest_path = tmp_path / "ZC-VPN-EXP-999" / "RUN-001" / "manifest.json"
    tampered_text = manifest_path.read_text(encoding="utf-8").replace(
        "weak_schema_length_baseline", "strict_schema_canonicalisation_mitigation"
    )
    manifest_path.write_text(tampered_text, encoding="utf-8")

    loaded = repo.load_manifest("ZC-VPN-EXP-999", "RUN-001")
    assert verify_manifest_integrity(loaded) is False


def test_save_comparison_writes_readable_json(tmp_path: Path, evidence_metrics: ExperimentMetrics) -> None:
    mitigation_metrics = evidence_metrics.model_copy(update={"run_id": "RUN-002"})
    report = ComparisonReport(
        experiment_id="ZC-VPN-EXP-999",
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        total_cases=22,
        baseline_metrics=evidence_metrics,
        mitigation_metrics=mitigation_metrics,
        block_rate_improvement=1.0,
        latency_overhead_ms=0.5,
        limitations=["synthetic model only"],
        generated_at=STARTED,
    )
    repo = LocalEvidenceRepository(tmp_path)

    path = repo.save_comparison("ZC-VPN-EXP-999", report)
    assert path == tmp_path / "ZC-VPN-EXP-999" / "comparison.json"
    loaded = ComparisonReport.model_validate_json(path.read_text(encoding="utf-8"))
    assert loaded == report
