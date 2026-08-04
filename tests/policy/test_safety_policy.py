import json
from datetime import UTC, datetime
from pathlib import Path

from zeroshield.models import ApprovalStatus, ExperimentDefinition
from zeroshield.policies import ExecutionContext, SafetyPolicy

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "experiments"

FIXED_TIME = datetime(2026, 8, 4, 9, 0, 0, tzinfo=UTC)


def _fixed_clock() -> datetime:
    return FIXED_TIME


def test_all_rules_pass_allows_execution_in_local_unit_test(
    valid_experiment_definition_data: dict,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    policy = SafetyPolicy()
    decision = policy.evaluate(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, clock=_fixed_clock
    )
    assert decision.allowed is True
    assert decision.reasons == []
    assert decision.evaluated_at == FIXED_TIME
    assert all(decision.rule_results.values())
    assert decision.policy_version == SafetyPolicy.POLICY_VERSION


def test_unapproved_experiment_denied_for_experiment_run(
    valid_experiment_definition_data: dict,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    policy = SafetyPolicy()
    decision = policy.evaluate(
        experiment, execution_context=ExecutionContext.EXPERIMENT_RUN, clock=_fixed_clock
    )
    assert decision.allowed is False
    assert decision.rule_results["SAFE-004"] is False
    assert any("SAFE-004" in reason for reason in decision.reasons)


def test_approved_experiment_allowed_for_experiment_run(
    valid_experiment_definition_data: dict,
) -> None:
    valid_experiment_definition_data["approval_status"] = ApprovalStatus.APPROVED.value
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    policy = SafetyPolicy()
    decision = policy.evaluate(
        experiment, execution_context=ExecutionContext.EXPERIMENT_RUN, clock=_fixed_clock
    )
    assert decision.allowed is True


def test_multiple_rule_failures_are_all_recorded(
    valid_experiment_definition_data: dict,
) -> None:
    valid_experiment_definition_data["external_targeting"] = True
    valid_experiment_definition_data["weaponised_payloads"] = True
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    policy = SafetyPolicy()
    decision = policy.evaluate(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, clock=_fixed_clock
    )
    assert decision.allowed is False
    assert decision.rule_results["SAFE-001"] is False
    assert decision.rule_results["SAFE-003"] is False
    assert len(decision.reasons) == 2


def test_default_execution_context_fails_closed(valid_experiment_definition_data: dict) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    policy = SafetyPolicy()
    decision = policy.evaluate(experiment, clock=_fixed_clock)
    assert decision.allowed is False


def test_valid_fixture_experiment_denied_until_approved() -> None:
    data = json.loads((FIXTURES_DIR / "valid_experiment_example.json").read_text(encoding="utf-8"))
    experiment = ExperimentDefinition(**data)
    policy = SafetyPolicy()
    decision = policy.evaluate(
        experiment, execution_context=ExecutionContext.EXPERIMENT_RUN, clock=_fixed_clock
    )
    assert decision.allowed is False
    assert decision.rule_results["SAFE-004"] is False
