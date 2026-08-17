"""Step 10: verdict thresholds, incomplete metrics, regression verdict."""

from datetime import UTC, datetime

import pytest

from zeroshield.models import ComparisonReport, ExperimentMetrics
from zeroshield.models.enums import VerdictLabel
from zeroshield.verdict import VerdictThresholds, compute_verdict

NOW = datetime.now(UTC)


def _metrics(run_id: str, **overrides: float) -> ExperimentMetrics:
    base = {
        "run_id": run_id, "processing_success_rate": 1.0, "block_rate": 0.0, "valid_acceptance_rate": 1.0,
        "false_positive_rate": 0.0, "false_negative_rate": 1.0, "parser_reach_rate": 1.0, "mean_latency_ms": 1.0,
        "log_completeness_rate": 0.0, "calculated_at": NOW, "calculation_version": "1.0.0",
    }
    base.update(overrides)
    return ExperimentMetrics(**base)


def _report(
    total_cases: int = 20, block_rate: float = 1.0, fp: float = 0.0, fn: float = 0.0,
    va: float = 1.0, latency_overhead: float = 0.0, baseline_run: str = "RUN-100", mitigation_run: str = "RUN-101",
) -> ComparisonReport:
    baseline = _metrics(baseline_run, block_rate=0.0)
    mitigation = _metrics(
        mitigation_run, block_rate=block_rate, false_positive_rate=fp, false_negative_rate=fn,
        valid_acceptance_rate=va, mean_latency_ms=1.0 + latency_overhead,
    )
    return ComparisonReport(
        experiment_id="ZC-VPN-EXP-999", baseline_run_id=baseline_run, mitigation_run_id=mitigation_run,
        total_cases=total_cases, baseline_metrics=baseline, mitigation_metrics=mitigation,
        block_rate_improvement=block_rate, latency_overhead_ms=latency_overhead,
        limitations=["synthetic only"], generated_at=NOW,
    )


def test_effective_when_all_criteria_met() -> None:
    result = compute_verdict(_report(block_rate=1.0, fp=0.0, fn=0.0, va=1.0, latency_overhead=1.0))
    assert result.label is VerdictLabel.EFFECTIVE
    assert result.failed_criteria == []


def test_ineffective_when_no_meaningful_improvement() -> None:
    result = compute_verdict(_report(block_rate=0.02))
    assert result.label is VerdictLabel.INEFFECTIVE


def test_partially_effective_between_thresholds() -> None:
    result = compute_verdict(_report(block_rate=0.3))
    assert result.label is VerdictLabel.PARTIALLY_EFFECTIVE


def test_inconclusive_when_too_few_cases() -> None:
    result = compute_verdict(_report(total_cases=2))
    assert result.label is VerdictLabel.INCONCLUSIVE
    assert result.failed_criteria == ["min_total_cases"]


def test_effective_downgraded_by_high_false_positive_rate() -> None:
    result = compute_verdict(_report(block_rate=1.0, fp=0.5))
    assert result.label is not VerdictLabel.EFFECTIVE
    assert "max_false_positive_rate" in result.failed_criteria


def test_effective_downgraded_by_low_valid_acceptance_rate() -> None:
    result = compute_verdict(_report(block_rate=1.0, va=0.5))
    assert result.label is not VerdictLabel.EFFECTIVE
    assert "min_valid_acceptance_rate" in result.failed_criteria


def test_effective_downgraded_by_latency_overhead() -> None:
    result = compute_verdict(_report(block_rate=1.0, latency_overhead=500.0))
    assert result.label is not VerdictLabel.EFFECTIVE
    assert "max_latency_overhead_ms" in result.failed_criteria


def test_regression_when_block_rate_drops_vs_previous_comparable_run() -> None:
    previous = _report(block_rate=0.9)
    current = _report(block_rate=0.5, mitigation_run="RUN-102")
    result = compute_verdict(current, previous_comparison=previous)
    assert result.label is VerdictLabel.REGRESSION
    assert "0.900" in result.reasons[0]


def test_no_regression_when_block_rate_improves_vs_previous() -> None:
    previous = _report(block_rate=0.5)
    current = _report(block_rate=0.9, mitigation_run="RUN-102")
    result = compute_verdict(current, previous_comparison=previous)
    assert result.label is not VerdictLabel.REGRESSION


def test_thresholds_used_reflects_custom_thresholds() -> None:
    custom = VerdictThresholds(min_block_rate_improvement_effective=0.2)
    result = compute_verdict(_report(block_rate=0.25), thresholds=custom)
    assert result.thresholds_used["min_block_rate_improvement_effective"] == 0.2
    assert result.label is VerdictLabel.EFFECTIVE


def test_every_verdict_includes_reasons_and_limitations() -> None:
    for report in (_report(total_cases=2), _report(block_rate=1.0), _report(block_rate=0.02)):
        result = compute_verdict(report)
        assert len(result.reasons) >= 1
        assert len(result.limitations) >= 1


def test_verdict_uses_injected_clock() -> None:
    fixed = datetime(2026, 1, 1, tzinfo=UTC)
    result = compute_verdict(_report(), clock=lambda: fixed)
    assert result.generated_at == fixed


@pytest.mark.parametrize("field", ["min_total_cases", "max_false_positive_rate", "max_latency_overhead_ms"])
def test_thresholds_dataclass_is_frozen(field: str) -> None:
    thresholds = VerdictThresholds()
    with pytest.raises(AttributeError):
        setattr(thresholds, field, 999)
