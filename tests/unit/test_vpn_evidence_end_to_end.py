import json
from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.metrics import calculate_metrics, compare
from zeroshield.models import ExperimentDefinition
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import (
    LocalEvidenceRepository,
    build_run_evidence,
    verify_manifest_integrity,
)
from zeroshield.runners import ExperimentRunner
from zeroshield.strategies.vpn import (
    StrictSchemaCanonicalisationMitigation,
    WeakSchemaLengthBaseline,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT_PATH = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"
DATASET_PATH = REPO_ROOT / "test_data" / "vpn" / "vpn_pre_auth_request_dataset.json"


def _load_vpn_experiment() -> ExperimentDefinition:
    data = json.loads(EXPERIMENT_PATH.read_text(encoding="utf-8"))
    return ExperimentDefinition(**data)


def test_vpn_evidence_generated_saved_and_verified_end_to_end(tmp_path: Path) -> None:
    experiment = _load_vpn_experiment()
    test_set, _ = load_test_set(DATASET_PATH)

    result = ExperimentRunner().run(
        experiment,
        DATASET_PATH,
        baseline=WeakSchemaLengthBaseline(),
        mitigation=StrictSchemaCanonicalisationMitigation(),
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="0123456",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )

    baseline_metrics = calculate_metrics("RUN-001", result.baseline.case_results, test_set.cases)
    mitigation_metrics = calculate_metrics("RUN-002", result.mitigation.case_results, test_set.cases)

    baseline_bundle = build_run_evidence(
        experiment, test_set.test_set_id, result.baseline, baseline_metrics, result.safety_decision
    )
    mitigation_bundle = build_run_evidence(
        experiment, test_set.test_set_id, result.mitigation, mitigation_metrics, result.safety_decision
    )
    report = compare(experiment.experiment_id, len(test_set.cases), baseline_metrics, mitigation_metrics)

    repo = LocalEvidenceRepository(tmp_path)
    baseline_dir = repo.save_run_evidence(baseline_bundle)
    mitigation_dir = repo.save_run_evidence(mitigation_bundle)
    comparison_path = repo.save_comparison(experiment.experiment_id, report)

    assert baseline_dir == tmp_path / "ZC-VPN-EXP-001" / "RUN-001"
    assert mitigation_dir == tmp_path / "ZC-VPN-EXP-001" / "RUN-002"
    assert comparison_path.is_file()

    loaded_baseline_manifest = repo.load_manifest("ZC-VPN-EXP-001", "RUN-001")
    loaded_mitigation_manifest = repo.load_manifest("ZC-VPN-EXP-001", "RUN-002")
    assert verify_manifest_integrity(loaded_baseline_manifest) is True
    assert verify_manifest_integrity(loaded_mitigation_manifest) is True

    assert loaded_baseline_manifest.test_set_sha256 == loaded_mitigation_manifest.test_set_sha256
    assert loaded_baseline_manifest.safety_decision == loaded_mitigation_manifest.safety_decision
    assert loaded_baseline_manifest.metrics.block_rate == 0.0
    assert loaded_mitigation_manifest.metrics.block_rate == 1.0
