from datetime import UTC, datetime

import pytest

from zeroshield.metrics import calculate_metrics
from zeroshield.models import CaseResult, TestCase


def _tc(case_id: str, expected: str) -> TestCase:
    return TestCase(
        case_id=case_id,
        category="malformed" if expected == "blocked" else "valid",
        input_data={},
        expected_outcome=expected,
        provenance="synthetic",
        version="1.0.0",
    )


def _cr(
    case_id: str,
    decision: str,
    *,
    parser_reached: bool = False,
    logged: bool = False,
    errored: bool = False,
    error_message: str | None = None,
    latency_ms: float = 1.0,
) -> CaseResult:
    return CaseResult(
        run_id="RUN-001",
        case_id=case_id,
        decision=decision,
        parser_reached=parser_reached,
        errored=errored,
        error_message=error_message,
        logged=logged,
        latency_ms=latency_ms,
    )


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)


def test_perfect_run_scores_maximally() -> None:
    test_cases = [_tc("TC-1", "accepted"), _tc("TC-2", "blocked")]
    case_results = [
        _cr("TC-1", "accepted", parser_reached=True),
        _cr("TC-2", "blocked", parser_reached=False, logged=True),
    ]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)

    assert metrics.processing_success_rate == 1.0
    assert metrics.block_rate == 1.0
    assert metrics.valid_acceptance_rate == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0
    assert metrics.log_completeness_rate == 1.0
    assert metrics.calculated_at == _fixed_clock()


def test_false_positive_counted_correctly() -> None:
    test_cases = [_tc("TC-1", "accepted")]
    case_results = [_cr("TC-1", "blocked", logged=True)]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)

    assert metrics.false_positive_rate == 1.0
    assert metrics.valid_acceptance_rate == 0.0


def test_false_negative_counted_correctly() -> None:
    test_cases = [_tc("TC-1", "blocked")]
    case_results = [_cr("TC-1", "accepted", parser_reached=True)]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)

    assert metrics.false_negative_rate == 1.0
    assert metrics.block_rate == 0.0
    assert metrics.parser_reach_rate == 1.0


def test_errored_case_excluded_from_confusion_matrix() -> None:
    test_cases = [_tc("TC-1", "accepted"), _tc("TC-2", "blocked")]
    case_results = [
        _cr("TC-1", "accepted", parser_reached=True),
        _cr("TC-2", "blocked", errored=True, error_message="boom", logged=True),
    ]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)

    assert metrics.processing_success_rate == 0.5
    # only TC-1 (accepted, correct) contributes to the confusion matrix
    assert metrics.valid_acceptance_rate == 1.0
    assert metrics.block_rate == 0.0  # no successful should-block cases at all


def test_parser_reach_rate_only_over_should_block_cases() -> None:
    test_cases = [_tc("TC-1", "accepted"), _tc("TC-2", "blocked")]
    case_results = [
        _cr("TC-1", "accepted", parser_reached=True),
        _cr("TC-2", "blocked", parser_reached=False, logged=True),
    ]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)
    assert metrics.parser_reach_rate == 0.0


def test_log_completeness_only_over_blocked_cases() -> None:
    test_cases = [_tc("TC-1", "blocked"), _tc("TC-2", "blocked")]
    case_results = [
        _cr("TC-1", "blocked", logged=True),
        _cr("TC-2", "blocked", logged=False),
    ]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)
    assert metrics.log_completeness_rate == 0.5


def test_mean_latency_computed_over_all_cases() -> None:
    test_cases = [_tc("TC-1", "accepted"), _tc("TC-2", "blocked")]
    case_results = [
        _cr("TC-1", "accepted", parser_reached=True, latency_ms=10.0),
        _cr("TC-2", "blocked", logged=True, latency_ms=20.0),
    ]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)
    assert metrics.mean_latency_ms == 15.0


def test_no_should_block_cases_gives_zero_rate_not_crash() -> None:
    test_cases = [_tc("TC-1", "accepted")]
    case_results = [_cr("TC-1", "accepted", parser_reached=True)]
    metrics = calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)
    assert metrics.block_rate == 0.0
    assert metrics.false_negative_rate == 0.0
    assert metrics.parser_reach_rate == 0.0


def test_unmatched_case_id_raises() -> None:
    test_cases = [_tc("TC-1", "accepted")]
    case_results = [_cr("TC-UNKNOWN", "accepted", parser_reached=True)]
    with pytest.raises(ValueError, match="no matching TestCase"):
        calculate_metrics("RUN-001", case_results, test_cases, clock=_fixed_clock)
