import json
from pathlib import Path
from typing import Any

import pytest

from zeroshield.models import ApprovalStatus, Decision, ExperimentDefinition
from zeroshield.policies import ExecutionContext
from zeroshield.runners import ExperimentRunner, PolicyRefusalError
from zeroshield.strategies import ProcessingStrategy, StrategyOutcome


class _RecordingAcceptAllStrategy(ProcessingStrategy):
    def __init__(self, strategy_id: str) -> None:
        self.strategy_id = strategy_id
        self.received: list[dict[str, Any]] = []

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        self.received.append(input_data)
        return StrategyOutcome(decision=Decision.ACCEPTED, parser_reached=True)


class _FailsOnMarkedCaseStrategy(ProcessingStrategy):
    strategy_id = "telecom_stub_mitigation"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        if input_data.get("crash"):
            raise RuntimeError("simulated strategy crash")
        return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False, logged=True)


def _telecom_cve() -> dict[str, Any]:
    return {
        "cve_id": "CVE-2023-23846",
        "domain": "TELECOM",
        "cvss_score": None,
        "cisa_kev": False,
        "epss_score": None,
        "trust_boundary": "GTP-U interface",
        "root_cause": "parser_message_handling_failure",
        "vendor_mitigation": "test",
        "mitigation_gap": "test",
        "source_urls": ["https://github.com/advisories/GHSA-3vj7-j945-rq57"],
        "retrieved_date": "2026-07-13",
    }


def _telecom_experiment(
    baseline_strategy: str, mitigation_strategy: str, approved: bool = False
) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id="ZC-TELECOM-EXP-999",
        title="Generic runner mechanics test experiment",
        domain="TELECOM",
        description="Synthetic experiment used only to prove the runner has no VPN coupling.",
        related_cves=[_telecom_cve()],
        failure_pattern="test failure pattern",
        root_cause="parser_message_handling_failure",
        vendor_mitigation="test",
        mitigation_gap="test",
        research_question="test question?",
        hypothesis="test hypothesis",
        safety_level="SYNTHETIC_ONLY",
        baseline_strategy=baseline_strategy,
        mitigation_strategy=mitigation_strategy,
        dataset_path="test_data/telecom/generic_runner_test_dataset.json",
        metrics_to_collect=["block_rate"],
        approval_status=ApprovalStatus.APPROVED if approved else ApprovalStatus.DRAFT,
    )


def _write_generic_dataset(path: Path, case_ids: list[str]) -> None:
    dataset = {
        "test_set_id": "generic-runner-test-v1",
        "version": "1.0.0",
        "domain": "TELECOM",
        "cases": [
            {
                "case_id": case_id,
                "category": "malformed",
                "input_data": {"seq": i, "crash": case_id == "TC-CRASH"},
                "expected_outcome": "blocked",
                "provenance": "synthetic",
                "version": "1.0.0",
            }
            for i, case_id in enumerate(case_ids)
        ],
    }
    path.write_text(json.dumps(dataset), encoding="utf-8")


def test_every_case_executed_once_by_each_strategy(tmp_path: Path) -> None:
    case_ids = ["TC-001", "TC-002", "TC-003"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    mitigation = _RecordingAcceptAllStrategy("telecom_stub_mitigation")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    result = ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="abc1234",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )

    assert len(result.baseline.case_results) == 3
    assert len(result.mitigation.case_results) == 3
    assert len(baseline.received) == 3
    assert len(mitigation.received) == 3


def test_both_strategies_receive_the_same_cases_in_order(tmp_path: Path) -> None:
    case_ids = ["TC-001", "TC-002", "TC-003"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    mitigation = _RecordingAcceptAllStrategy("telecom_stub_mitigation")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="abc1234",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )

    assert baseline.received == mitigation.received
    assert [d["seq"] for d in baseline.received] == [0, 1, 2]


def test_results_stay_associated_with_correct_case_ids(tmp_path: Path) -> None:
    case_ids = ["TC-AAA", "TC-BBB", "TC-CCC"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    mitigation = _RecordingAcceptAllStrategy("telecom_stub_mitigation")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    result = ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="abc1234",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )

    baseline_ids = [r.case_id for r in result.baseline.case_results]
    mitigation_ids = [r.case_id for r in result.mitigation.case_results]
    assert baseline_ids == case_ids
    assert mitigation_ids == case_ids
    for r in result.baseline.case_results:
        assert r.run_id == "RUN-001"
    for r in result.mitigation.case_results:
        assert r.run_id == "RUN-002"


def test_strategy_failure_is_isolated_and_recorded_safely(tmp_path: Path) -> None:
    case_ids = ["TC-OK-1", "TC-CRASH", "TC-OK-2"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    mitigation = _FailsOnMarkedCaseStrategy()
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    result = ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="abc1234",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )

    results_by_id = {r.case_id: r for r in result.mitigation.case_results}
    assert len(results_by_id) == 3

    crashed = results_by_id["TC-CRASH"]
    assert crashed.errored is True
    assert crashed.error_message is not None
    assert "simulated strategy crash" in crashed.error_message
    assert crashed.decision == Decision.BLOCKED
    assert crashed.parser_reached is False

    ok_1 = results_by_id["TC-OK-1"]
    ok_2 = results_by_id["TC-OK-2"]
    assert ok_1.errored is False
    assert ok_2.errored is False
    assert ok_1.decision == Decision.BLOCKED
    assert ok_2.decision == Decision.BLOCKED

    assert result.mitigation.run.status.value == "completed"


def test_refuses_to_run_unapproved_experiment_in_real_run_context(tmp_path: Path) -> None:
    case_ids = ["TC-001"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    mitigation = _RecordingAcceptAllStrategy("telecom_stub_mitigation")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    with pytest.raises(PolicyRefusalError) as exc_info:
        ExperimentRunner().run(
            experiment,
            dataset_path,
            baseline=baseline,
            mitigation=mitigation,
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="abc1234",
            execution_context=ExecutionContext.EXPERIMENT_RUN,
        )
    assert exc_info.value.decision.allowed is False
    assert len(baseline.received) == 0


def test_approved_experiment_runs_in_real_run_context(tmp_path: Path) -> None:
    case_ids = ["TC-001"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    mitigation = _RecordingAcceptAllStrategy("telecom_stub_mitigation")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation", approved=True)

    result = ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="abc1234",
        execution_context=ExecutionContext.EXPERIMENT_RUN,
    )
    assert len(result.baseline.case_results) == 1


def test_mismatched_baseline_strategy_id_rejected(tmp_path: Path) -> None:
    case_ids = ["TC-001"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    wrong_baseline = _RecordingAcceptAllStrategy("some_other_strategy")
    mitigation = _RecordingAcceptAllStrategy("telecom_stub_mitigation")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    with pytest.raises(ValueError, match="baseline strategy_id"):
        ExperimentRunner().run(
            experiment,
            dataset_path,
            baseline=wrong_baseline,
            mitigation=mitigation,
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="abc1234",
            execution_context=ExecutionContext.LOCAL_UNIT_TEST,
        )


def test_mismatched_mitigation_strategy_id_rejected(tmp_path: Path) -> None:
    case_ids = ["TC-001"]
    dataset_path = tmp_path / "dataset.json"
    _write_generic_dataset(dataset_path, case_ids)

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    wrong_mitigation = _RecordingAcceptAllStrategy("some_other_strategy")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    with pytest.raises(ValueError, match="mitigation strategy_id"):
        ExperimentRunner().run(
            experiment,
            dataset_path,
            baseline=baseline,
            mitigation=wrong_mitigation,
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="abc1234",
            execution_context=ExecutionContext.LOCAL_UNIT_TEST,
        )


def test_dataset_domain_mismatch_rejected(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.json"
    dataset = {
        "test_set_id": "wrong-domain-v1",
        "version": "1.0.0",
        "domain": "VPN",
        "cases": [
            {
                "case_id": "TC-001",
                "category": "malformed",
                "input_data": {},
                "expected_outcome": "blocked",
                "provenance": "synthetic",
                "version": "1.0.0",
            }
        ],
    }
    dataset_path.write_text(json.dumps(dataset), encoding="utf-8")

    baseline = _RecordingAcceptAllStrategy("telecom_stub_baseline")
    mitigation = _RecordingAcceptAllStrategy("telecom_stub_mitigation")
    experiment = _telecom_experiment("telecom_stub_baseline", "telecom_stub_mitigation")

    with pytest.raises(ValueError, match="dataset domain"):
        ExperimentRunner().run(
            experiment,
            dataset_path,
            baseline=baseline,
            mitigation=mitigation,
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="abc1234",
            execution_context=ExecutionContext.LOCAL_UNIT_TEST,
        )
