import json
from pathlib import Path

from zeroshield.metrics import calculate_metrics, compare
from zeroshield.models import ExperimentDefinition, TestCase
from zeroshield.policies import ExecutionContext
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


def _load_vpn_test_cases() -> list[TestCase]:
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    return [TestCase(**c) for c in dataset["cases"]]


def test_vpn_metrics_and_comparison_reproduce_known_research_findings() -> None:
    experiment = _load_vpn_experiment()
    test_cases = _load_vpn_test_cases()

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

    baseline_metrics = calculate_metrics("RUN-001", result.baseline.case_results, test_cases)
    mitigation_metrics = calculate_metrics("RUN-002", result.mitigation.case_results, test_cases)

    # 6 cases should be accepted (4 valid + 2 accepted-boundary), 16 should be blocked
    # (15 malformed + 1 blocked-boundary) - see Milestones 5-7.
    assert baseline_metrics.processing_success_rate == 1.0
    assert baseline_metrics.block_rate == 0.0
    assert baseline_metrics.valid_acceptance_rate == 1.0
    assert baseline_metrics.false_positive_rate == 0.0
    assert baseline_metrics.false_negative_rate == 1.0
    assert baseline_metrics.parser_reach_rate == 1.0
    assert baseline_metrics.log_completeness_rate == 0.0  # baseline never blocks -> nothing to log

    assert mitigation_metrics.processing_success_rate == 1.0
    assert mitigation_metrics.block_rate == 1.0
    assert mitigation_metrics.valid_acceptance_rate == 1.0
    assert mitigation_metrics.false_positive_rate == 0.0
    assert mitigation_metrics.false_negative_rate == 0.0
    assert mitigation_metrics.parser_reach_rate == 0.0
    assert mitigation_metrics.log_completeness_rate == 1.0

    report = compare(experiment.experiment_id, 22, baseline_metrics, mitigation_metrics)
    assert report.block_rate_improvement == 1.0
    assert report.total_cases == 22
    assert len(report.limitations) >= 1
