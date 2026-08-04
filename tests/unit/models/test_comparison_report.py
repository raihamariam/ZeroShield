from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from zeroshield.models import ComparisonReport, ExperimentMetrics


def _metrics(run_id: str, **overrides: object) -> ExperimentMetrics:
    data = {
        "run_id": run_id,
        "processing_success_rate": 1.0,
        "block_rate": 0.95,
        "valid_acceptance_rate": 0.99,
        "false_positive_rate": 0.01,
        "false_negative_rate": 0.05,
        "parser_reach_rate": 0.1,
        "mean_latency_ms": 12.5,
        "log_completeness_rate": 1.0,
        "calculated_at": datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
        "calculation_version": "1.0.0",
    }
    data.update(overrides)
    return ExperimentMetrics(**data)


def _report(**overrides: object) -> ComparisonReport:
    data = {
        "experiment_id": "ZC-VPN-EXP-001",
        "baseline_run_id": "RUN-001",
        "mitigation_run_id": "RUN-002",
        "total_cases": 22,
        "baseline_metrics": _metrics("RUN-001"),
        "mitigation_metrics": _metrics("RUN-002"),
        "block_rate_improvement": 1.0,
        "latency_overhead_ms": 0.5,
        "limitations": ["synthetic model only"],
        "generated_at": datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC),
    }
    data.update(overrides)
    return ComparisonReport(**data)


def test_valid_comparison_report_parses() -> None:
    report = _report()
    assert report.total_cases == 22
    assert report.block_rate_improvement == 1.0


def test_same_run_id_for_both_modes_rejected() -> None:
    with pytest.raises(ValidationError, match="must be different runs"):
        _report(mitigation_run_id="RUN-001", mitigation_metrics=_metrics("RUN-001"))


def test_baseline_metrics_run_id_mismatch_rejected() -> None:
    with pytest.raises(ValidationError, match="baseline_metrics.run_id must match"):
        _report(baseline_metrics=_metrics("RUN-999"))


def test_mitigation_metrics_run_id_mismatch_rejected() -> None:
    with pytest.raises(ValidationError, match="mitigation_metrics.run_id must match"):
        _report(mitigation_metrics=_metrics("RUN-999"))


def test_empty_limitations_rejected() -> None:
    with pytest.raises(ValidationError, match="limitations"):
        _report(limitations=[])


def test_total_cases_must_be_positive() -> None:
    with pytest.raises(ValidationError, match="total_cases"):
        _report(total_cases=0)


def test_comparison_report_is_immutable() -> None:
    report = _report()
    with pytest.raises(ValidationError):
        report.total_cases = 100
