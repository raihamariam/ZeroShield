"""Audit Part C: an unsafe-configured (not merely unapproved) experiment must be refused."""

import json
from pathlib import Path
from typing import Any

import pytest

from zeroshield.models import ApprovalStatus, ExperimentDefinition
from zeroshield.policies import ExecutionContext
from zeroshield.runners import ExperimentRunner, PolicyRefusalError
from zeroshield.strategies.vpn import (
    StrictSchemaCanonicalisationMitigation,
    WeakSchemaLengthBaseline,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT_PATH = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"
DATASET_PATH = REPO_ROOT / "test_data" / "vpn" / "vpn_pre_auth_request_dataset.json"


class _CountingStrategy(WeakSchemaLengthBaseline):
    """Wraps the real baseline but counts calls, to prove zero cases were ever processed."""

    def __init__(self) -> None:
        self.call_count = 0

    def process(self, input_data: dict[str, Any]) -> Any:
        self.call_count += 1
        return super().process(input_data)


def test_experiment_declaring_external_targeting_is_refused_even_if_approved() -> None:
    data = json.loads(EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["external_targeting"] = True
    data["approval_status"] = ApprovalStatus.APPROVED.value
    unsafe_experiment = ExperimentDefinition(**data)

    baseline = _CountingStrategy()
    mitigation = StrictSchemaCanonicalisationMitigation()

    with pytest.raises(PolicyRefusalError) as exc_info:
        ExperimentRunner().run(
            unsafe_experiment,
            DATASET_PATH,
            baseline=baseline,
            mitigation=mitigation,
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="0123456",
            execution_context=ExecutionContext.EXPERIMENT_RUN,
        )

    assert exc_info.value.decision.allowed is False
    assert exc_info.value.decision.rule_results["SAFE-001"] is False
    assert any("SAFE-001" in reason for reason in exc_info.value.decision.reasons)
    # the strongest proof: the baseline strategy was never even invoked
    assert baseline.call_count == 0


def test_experiment_declaring_weaponised_payloads_is_refused_even_if_approved() -> None:
    data = json.loads(EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["weaponised_payloads"] = True
    data["approval_status"] = ApprovalStatus.APPROVED.value
    unsafe_experiment = ExperimentDefinition(**data)

    baseline = _CountingStrategy()
    mitigation = StrictSchemaCanonicalisationMitigation()

    with pytest.raises(PolicyRefusalError) as exc_info:
        ExperimentRunner().run(
            unsafe_experiment,
            DATASET_PATH,
            baseline=baseline,
            mitigation=mitigation,
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="0123456",
            execution_context=ExecutionContext.EXPERIMENT_RUN,
        )

    assert exc_info.value.decision.rule_results["SAFE-003"] is False
    assert baseline.call_count == 0
