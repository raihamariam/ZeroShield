from datetime import UTC, datetime

from zeroshield.metrics import compare
from zeroshield.metrics.comparator import STANDARD_LIMITATIONS
from zeroshield.models import ExperimentMetrics


def _metrics(run_id: str, block_rate: float, mean_latency_ms: float) -> ExperimentMetrics:
    return ExperimentMetrics(
        run_id=run_id,
        processing_success_rate=1.0,
        block_rate=block_rate,
        valid_acceptance_rate=1.0,
        false_positive_rate=0.0,
        false_negative_rate=1.0 - block_rate,
        parser_reach_rate=1.0 - block_rate,
        mean_latency_ms=mean_latency_ms,
        log_completeness_rate=1.0,
        calculated_at=datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
        calculation_version="1.0.0",
    )


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC)


def test_compare_computes_block_rate_improvement() -> None:
    baseline = _metrics("RUN-001", block_rate=0.0, mean_latency_ms=1.0)
    mitigation = _metrics("RUN-002", block_rate=1.0, mean_latency_ms=1.5)

    report = compare("ZC-VPN-EXP-001", 22, baseline, mitigation, clock=_fixed_clock)

    assert report.block_rate_improvement == 1.0
    assert report.latency_overhead_ms == 0.5
    assert report.baseline_run_id == "RUN-001"
    assert report.mitigation_run_id == "RUN-002"
    assert report.total_cases == 22
    assert report.generated_at == _fixed_clock()


def test_compare_includes_standard_limitations() -> None:
    baseline = _metrics("RUN-001", block_rate=0.0, mean_latency_ms=1.0)
    mitigation = _metrics("RUN-002", block_rate=1.0, mean_latency_ms=1.5)
    report = compare("ZC-VPN-EXP-001", 22, baseline, mitigation, clock=_fixed_clock)
    assert report.limitations == STANDARD_LIMITATIONS


def test_compare_handles_mitigation_being_faster() -> None:
    baseline = _metrics("RUN-001", block_rate=0.0, mean_latency_ms=5.0)
    mitigation = _metrics("RUN-002", block_rate=1.0, mean_latency_ms=2.0)
    report = compare("ZC-VPN-EXP-001", 22, baseline, mitigation, clock=_fixed_clock)
    assert report.latency_overhead_ms == -3.0
