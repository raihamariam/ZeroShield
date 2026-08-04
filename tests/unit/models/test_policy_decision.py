import pytest
from pydantic import ValidationError

from zeroshield.models import PolicyDecision


def test_valid_allowed_decision_parses(valid_policy_decision_data: dict) -> None:
    decision = PolicyDecision(**valid_policy_decision_data)
    assert decision.allowed is True


def test_valid_denied_decision_parses(valid_policy_decision_data: dict) -> None:
    valid_policy_decision_data["allowed"] = False
    valid_policy_decision_data["rule_results"] = {"SAFE-001": True, "SAFE-002": False}
    valid_policy_decision_data["reasons"] = ["SAFE-002 failed: external_targeting was true"]
    decision = PolicyDecision(**valid_policy_decision_data)
    assert decision.allowed is False


def test_denied_without_reasons_rejected(valid_policy_decision_data: dict) -> None:
    valid_policy_decision_data["allowed"] = False
    valid_policy_decision_data["rule_results"] = {"SAFE-001": False}
    with pytest.raises(ValidationError, match="reasons must be provided"):
        PolicyDecision(**valid_policy_decision_data)


def test_denied_with_all_rules_passing_rejected(valid_policy_decision_data: dict) -> None:
    valid_policy_decision_data["allowed"] = False
    valid_policy_decision_data["reasons"] = ["inconsistent"]
    with pytest.raises(ValidationError, match="at least one failed"):
        PolicyDecision(**valid_policy_decision_data)


def test_allowed_with_a_failed_rule_rejected(valid_policy_decision_data: dict) -> None:
    valid_policy_decision_data["rule_results"] = {"SAFE-001": True, "SAFE-002": False}
    with pytest.raises(ValidationError, match="all rule_results entries to pass"):
        PolicyDecision(**valid_policy_decision_data)


def test_invalid_rule_id_pattern_rejected(valid_policy_decision_data: dict) -> None:
    valid_policy_decision_data["rule_results"] = {"NOT-A-RULE": True}
    with pytest.raises(ValidationError):
        PolicyDecision(**valid_policy_decision_data)
