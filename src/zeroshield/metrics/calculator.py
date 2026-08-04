from collections.abc import Callable
from datetime import UTC, datetime

from zeroshield.models import CaseResult, Decision, ExperimentMetrics, TestCase


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _safe_rate(numerator: int, denominator: int) -> float:
    # By convention, an empty applicable group scores 0.0 rather than raising or being
    # treated as vacuously 1.0 - callers should also check the relevant count directly.
    if denominator == 0:
        return 0.0
    return numerator / denominator


def calculate_metrics(
    run_id: str,
    case_results: list[CaseResult],
    test_cases: list[TestCase],
    *,
    calculation_version: str = "1.0.0",
    clock: Callable[[], datetime] = _utc_now,
) -> ExperimentMetrics:
    """Compute FR-008 metrics from raw results, using TestCase.expected_outcome as ground truth."""
    expected_by_case_id = {tc.case_id: tc.expected_outcome for tc in test_cases}

    successful: list[tuple[CaseResult, Decision]] = []
    for result in case_results:
        if result.case_id not in expected_by_case_id:
            raise ValueError(f"case_id '{result.case_id}' has no matching TestCase; cannot score it")
        if not result.errored:
            successful.append((result, expected_by_case_id[result.case_id]))

    total = len(case_results)
    processing_success_rate = _safe_rate(len(successful), total)

    should_block = [(r, e) for r, e in successful if e == Decision.BLOCKED]
    should_accept = [(r, e) for r, e in successful if e == Decision.ACCEPTED]

    true_positive = sum(1 for r, _ in should_block if r.decision == Decision.BLOCKED)
    false_negative = sum(1 for r, _ in should_block if r.decision == Decision.ACCEPTED)
    true_negative = sum(1 for r, _ in should_accept if r.decision == Decision.ACCEPTED)
    false_positive = sum(1 for r, _ in should_accept if r.decision == Decision.BLOCKED)

    block_rate = _safe_rate(true_positive, len(should_block))
    valid_acceptance_rate = _safe_rate(true_negative, len(should_accept))
    false_positive_rate = _safe_rate(false_positive, len(should_accept))
    false_negative_rate = _safe_rate(false_negative, len(should_block))
    parser_reach_rate = _safe_rate(
        sum(1 for r, _ in should_block if r.parser_reached), len(should_block)
    )

    blocked_results = [r for r, _ in successful if r.decision == Decision.BLOCKED]
    log_completeness_rate = _safe_rate(
        sum(1 for r in blocked_results if r.logged), len(blocked_results)
    )

    mean_latency_ms = sum(r.latency_ms for r in case_results) / total if total else 0.0

    return ExperimentMetrics(
        run_id=run_id,
        processing_success_rate=processing_success_rate,
        block_rate=block_rate,
        valid_acceptance_rate=valid_acceptance_rate,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        parser_reach_rate=parser_reach_rate,
        mean_latency_ms=mean_latency_ms,
        log_completeness_rate=log_completeness_rate,
        calculated_at=clock(),
        calculation_version=calculation_version,
    )
