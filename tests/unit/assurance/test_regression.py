"""Step 10: each deterministic regression rule, independently."""

from datetime import UTC, datetime

from zeroshield.assurance.models import ControlValidation
from zeroshield.assurance.regression import detect_regressions

NOW = datetime.now(UTC)


def _validation(**overrides: object) -> ControlValidation:
    base = {
        "validation_id": "VAL-1", "control_id": "C", "version_id": "V1", "experiment_id": "ZC-VPN-EXP-001",
        "baseline_run_id": "RUN-1", "mitigation_run_id": "RUN-2", "total_cases": 10,
        "block_rate_improvement": 0.6, "false_positive_rate": 0.01, "false_negative_rate": 0.01,
        "valid_acceptance_rate": 0.99, "parser_reach_rate": 0.05, "latency_overhead_ms": 1.0,
        "verdict_label": "effective", "validated_at": NOW,
    }
    base.update(overrides)
    return ControlValidation(**base)


def test_identical_validations_are_not_a_regression() -> None:
    previous = _validation()
    latest = _validation(validation_id="VAL-2")
    result = detect_regressions(previous, latest)
    assert result.is_regression is False
    assert result.reasons == []


def test_verdict_deterioration_is_flagged() -> None:
    previous = _validation(verdict_label="effective")
    latest = _validation(verdict_label="ineffective")
    result = detect_regressions(previous, latest)
    assert result.is_regression is True
    assert any("Verdict deteriorated" in r for r in result.reasons)


def test_material_block_rate_improvement_drop_is_flagged() -> None:
    previous = _validation(block_rate_improvement=0.6)
    latest = _validation(block_rate_improvement=0.4)  # drop of 0.2 > default 0.10 threshold
    result = detect_regressions(previous, latest)
    assert result.is_regression is True
    assert any("block_rate_improvement dropped" in r for r in result.reasons)


def test_small_block_rate_drop_within_threshold_is_not_flagged() -> None:
    previous = _validation(block_rate_improvement=0.60)
    latest = _validation(block_rate_improvement=0.55)  # drop of 0.05 < 0.10 threshold
    result = detect_regressions(previous, latest)
    assert result.is_regression is False


def test_false_positive_rate_increase_is_flagged() -> None:
    previous = _validation(false_positive_rate=0.01)
    latest = _validation(false_positive_rate=0.10)
    result = detect_regressions(previous, latest)
    assert result.is_regression is True
    assert any("false_positive_rate increased" in r for r in result.reasons)


def test_false_negative_rate_increase_is_flagged() -> None:
    previous = _validation(false_negative_rate=0.01)
    latest = _validation(false_negative_rate=0.10)
    result = detect_regressions(previous, latest)
    assert result.is_regression is True
    assert any("false_negative_rate increased" in r for r in result.reasons)


def test_valid_acceptance_rate_drop_is_flagged() -> None:
    previous = _validation(valid_acceptance_rate=0.99)
    latest = _validation(valid_acceptance_rate=0.80)
    result = detect_regressions(previous, latest)
    assert result.is_regression is True
    assert any("valid_acceptance_rate dropped" in r for r in result.reasons)


def test_parser_exposure_increase_is_flagged() -> None:
    previous = _validation(parser_reach_rate=0.05)
    latest = _validation(parser_reach_rate=0.50)
    result = detect_regressions(previous, latest)
    assert result.is_regression is True
    assert any("parser_reach_rate" in r and "increased" in r for r in result.reasons)


def test_multiple_simultaneous_regressions_all_reported() -> None:
    previous = _validation(verdict_label="effective", false_positive_rate=0.01)
    latest = _validation(verdict_label="regression", false_positive_rate=0.20)
    result = detect_regressions(previous, latest)
    assert result.is_regression is True
    assert len(result.reasons) >= 2


def test_thresholds_used_are_reported() -> None:
    result = detect_regressions(_validation(), _validation(validation_id="VAL-2"))
    assert result.thresholds_used["max_block_rate_improvement_drop"] == 0.10
