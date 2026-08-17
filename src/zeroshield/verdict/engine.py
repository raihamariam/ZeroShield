"""Deterministic, explainable verdict engine (V2 Phase 3, Step 7).

Every verdict is pure arithmetic over already-computed ComparisonReport
metrics against configurable thresholds - no model, no learned weighting, no
AI anywhere in this module or called by it. AI never decides a trusted
verdict (V2 engineering rule) is enforced by construction: nothing here ever
calls out to zeroshield's (nonexistent, by design) AI layer.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from zeroshield.models import ComparisonReport
from zeroshield.models.enums import VerdictLabel


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class VerdictThresholds:
    """Every threshold is a maximum/minimum measurable bound - the one
    adjustable configuration point for this engine (mirrors
    zeroshield.intelligence.priority.PriorityWeights' role for scoring)."""

    min_total_cases: int = 5
    min_block_rate_improvement_effective: float = 0.5
    min_block_rate_improvement_partial: float = 0.1
    max_false_positive_rate: float = 0.05
    max_false_negative_rate: float = 0.10
    min_valid_acceptance_rate: float = 0.95
    max_latency_overhead_ms: float = 100.0
    regression_block_rate_drop: float = 0.0  # any drop below the previous comparable run's block_rate


@dataclass(frozen=True)
class VerdictResult:
    label: VerdictLabel
    reasons: list[str]
    thresholds_used: dict[str, float]
    failed_criteria: list[str]
    limitations: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=_utc_now)


DEFAULT_THRESHOLDS = VerdictThresholds()

_STANDARD_LIMITATIONS = [
    (
        "Verdict reflects only the cases included in this comparison's dataset version, not "
        "general real-world attack traffic."
    ),
    (
        "Verdict is deterministic and threshold-based; it is not a certification of production "
        "readiness and does not replace manual security review."
    ),
]


def _thresholds_dict(t: VerdictThresholds) -> dict[str, float]:
    return {
        "min_total_cases": float(t.min_total_cases),
        "min_block_rate_improvement_effective": t.min_block_rate_improvement_effective,
        "min_block_rate_improvement_partial": t.min_block_rate_improvement_partial,
        "max_false_positive_rate": t.max_false_positive_rate,
        "max_false_negative_rate": t.max_false_negative_rate,
        "min_valid_acceptance_rate": t.min_valid_acceptance_rate,
        "max_latency_overhead_ms": t.max_latency_overhead_ms,
        "regression_block_rate_drop": t.regression_block_rate_drop,
    }


def compute_verdict(
    comparison: ComparisonReport,
    *,
    previous_comparison: ComparisonReport | None = None,
    thresholds: VerdictThresholds = DEFAULT_THRESHOLDS,
    clock: Callable[[], datetime] = _utc_now,
) -> VerdictResult:
    thresholds_used = _thresholds_dict(thresholds)
    limitations = list(_STANDARD_LIMITATIONS)

    if comparison.total_cases < thresholds.min_total_cases:
        return VerdictResult(
            label=VerdictLabel.INCONCLUSIVE,
            reasons=[
                (
                    f"Only {comparison.total_cases} case(s) in this comparison, below the required "
                    f"minimum of {thresholds.min_total_cases} for a trustworthy verdict."
                )
            ],
            thresholds_used=thresholds_used,
            failed_criteria=["min_total_cases"],
            limitations=limitations,
            generated_at=clock(),
        )

    m = comparison.mitigation_metrics
    reasons: list[str] = []
    failed: list[str] = []

    if previous_comparison is not None:
        previous_block_rate = previous_comparison.mitigation_metrics.block_rate
        drop = previous_block_rate - m.block_rate
        if drop > thresholds.regression_block_rate_drop:
            reasons.append(
                f"Mitigation block_rate regressed from {previous_block_rate:.3f} (previous "
                f"comparable run) to {m.block_rate:.3f}, a drop of {drop:.3f}, exceeding the "
                f"allowed {thresholds.regression_block_rate_drop:.3f}."
            )
            return VerdictResult(
                label=VerdictLabel.REGRESSION,
                reasons=reasons,
                thresholds_used=thresholds_used,
                failed_criteria=["regression_block_rate_drop"],
                limitations=limitations,
                generated_at=clock(),
            )

    fp_ok = m.false_positive_rate <= thresholds.max_false_positive_rate
    fn_ok = m.false_negative_rate <= thresholds.max_false_negative_rate
    va_ok = m.valid_acceptance_rate >= thresholds.min_valid_acceptance_rate
    latency_ok = comparison.latency_overhead_ms <= thresholds.max_latency_overhead_ms
    improvement = comparison.block_rate_improvement

    reasons.append(f"block_rate_improvement={improvement:.3f}")
    reasons.append(f"mitigation false_positive_rate={m.false_positive_rate:.3f}")
    reasons.append(f"mitigation false_negative_rate={m.false_negative_rate:.3f}")
    reasons.append(f"mitigation valid_acceptance_rate={m.valid_acceptance_rate:.3f}")
    reasons.append(f"latency_overhead_ms={comparison.latency_overhead_ms:.2f}")

    if not fp_ok:
        failed.append("max_false_positive_rate")
    if not fn_ok:
        failed.append("max_false_negative_rate")
    if not va_ok:
        failed.append("min_valid_acceptance_rate")
    if not latency_ok:
        failed.append("max_latency_overhead_ms")

    if (
        improvement >= thresholds.min_block_rate_improvement_effective
        and fp_ok
        and fn_ok
        and va_ok
        and latency_ok
    ):
        label = VerdictLabel.EFFECTIVE
        reasons.insert(0, "All effectiveness criteria met at the EFFECTIVE thresholds.")
    elif improvement >= thresholds.min_block_rate_improvement_partial and va_ok:
        label = VerdictLabel.PARTIALLY_EFFECTIVE
        if improvement < thresholds.min_block_rate_improvement_effective:
            failed.append("min_block_rate_improvement_effective")
        reasons.insert(
            0,
            "Meaningful improvement observed but one or more EFFECTIVE-level criteria were not met.",
        )
    else:
        label = VerdictLabel.INEFFECTIVE
        if improvement < thresholds.min_block_rate_improvement_partial:
            failed.append("min_block_rate_improvement_partial")
        reasons.insert(0, "Improvement did not meet even the PARTIALLY_EFFECTIVE threshold.")

    return VerdictResult(
        label=label,
        reasons=reasons,
        thresholds_used=thresholds_used,
        failed_criteria=failed,
        limitations=limitations,
        generated_at=clock(),
    )
