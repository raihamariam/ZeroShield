import json
from pathlib import Path

from zeroshield.models import Decision, ExperimentDefinition, TestCaseCategory
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


def test_vpn_experiment_runs_end_to_end_through_the_runner() -> None:
    experiment = _load_vpn_experiment()

    # ZC-VPN-EXP-001 is still draft (D-01 unresolved) — LOCAL_UNIT_TEST is the legitimate
    # SAFE-004 carve-out for exercising a valid-but-unapproved experiment definition.
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

    assert result.baseline.run.experiment_id == "ZC-VPN-EXP-001"
    assert result.mitigation.run.experiment_id == "ZC-VPN-EXP-001"
    assert result.baseline.strategy_id == "weak_schema_length_baseline"
    assert result.mitigation.strategy_id == "strict_schema_canonicalisation_mitigation"
    assert result.baseline.run.dataset_hash == result.mitigation.run.dataset_hash

    assert len(result.baseline.case_results) == 22
    assert len(result.mitigation.case_results) == 22
    assert not any(r.errored for r in result.baseline.case_results)
    assert not any(r.errored for r in result.mitigation.case_results)


def test_vpn_end_to_end_reproduces_known_baseline_and_mitigation_gap() -> None:
    experiment = _load_vpn_experiment()
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    malformed_ids = {
        c["case_id"] for c in dataset["cases"] if c["category"] == TestCaseCategory.MALFORMED.value
    }
    valid_ids = {
        c["case_id"] for c in dataset["cases"] if c["category"] == TestCaseCategory.VALID.value
    }

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

    baseline_malformed = [r for r in result.baseline.case_results if r.case_id in malformed_ids]
    mitigation_malformed = [r for r in result.mitigation.case_results if r.case_id in malformed_ids]
    baseline_valid = [r for r in result.baseline.case_results if r.case_id in valid_ids]
    mitigation_valid = [r for r in result.mitigation.case_results if r.case_id in valid_ids]

    assert all(r.decision == Decision.ACCEPTED for r in baseline_malformed)
    assert all(r.decision == Decision.BLOCKED for r in mitigation_malformed)
    assert all(r.decision == Decision.ACCEPTED for r in baseline_valid)
    assert all(r.decision == Decision.ACCEPTED for r in mitigation_valid)
