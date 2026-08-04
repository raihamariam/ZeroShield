from collections.abc import Callable
from datetime import UTC, datetime

from zeroshield.models import ComparisonReport, ExperimentMetrics

# Reuses the SRS §6.1 VPN Limitation wording verbatim rather than inventing new claims.
STANDARD_LIMITATIONS = [
    (
        "Results reflect a synthetic, abstracted model of the failure pattern and do not "
        "prove mitigation effectiveness for the original vendor product."
    ),
    (
        "Metrics are computed only over the cases included in this dataset version and are "
        "not a general claim about real-world attack traffic distributions."
    ),
]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def compare(
    experiment_id: str,
    total_cases: int,
    baseline_metrics: ExperimentMetrics,
    mitigation_metrics: ExperimentMetrics,
    *,
    clock: Callable[[], datetime] = _utc_now,
) -> ComparisonReport:
    """Build a baseline-vs-mitigated comparison report, per FR-009 and AC-07."""
    return ComparisonReport(
        experiment_id=experiment_id,
        baseline_run_id=baseline_metrics.run_id,
        mitigation_run_id=mitigation_metrics.run_id,
        total_cases=total_cases,
        baseline_metrics=baseline_metrics,
        mitigation_metrics=mitigation_metrics,
        block_rate_improvement=mitigation_metrics.block_rate - baseline_metrics.block_rate,
        latency_overhead_ms=mitigation_metrics.mean_latency_ms - baseline_metrics.mean_latency_ms,
        limitations=list(STANDARD_LIMITATIONS),
        generated_at=clock(),
    )
