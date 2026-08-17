"""Deterministic regression detection (V2 Phase 5, Step 10).

Same spirit as zeroshield.verdict.engine.compute_verdict: pure arithmetic
over two already-recorded ControlValidation snapshots against configurable
thresholds - no model, no learned weighting, no AI anywhere in this module.
AI may explain a regression (zeroshield.ai.research_analyst_service.
explain_regression), never independently declare one - this module is the
only place a regression is ever decided.
"""

from dataclasses import dataclass, field

from zeroshield.assurance.models import ControlValidation
from zeroshield.models.enums import VerdictLabel

_VERDICT_SEVERITY: dict[str, int] = {
    VerdictLabel.EFFECTIVE.value: 4,
    VerdictLabel.PARTIALLY_EFFECTIVE.value: 3,
    VerdictLabel.INCONCLUSIVE.value: 2,
    VerdictLabel.INEFFECTIVE.value: 1,
    VerdictLabel.REGRESSION.value: 0,
}


@dataclass(frozen=True)
class RegressionThresholds:
    """Every threshold is a maximum tolerated *degradation* between two
    consecutive validations of the same control - the one adjustable
    configuration point, mirroring zeroshield.verdict.engine.
    VerdictThresholds' role for verdicts."""

    max_block_rate_improvement_drop: float = 0.10
    max_false_positive_rate_increase: float = 0.05
    max_false_negative_rate_increase: float = 0.05
    max_valid_acceptance_rate_drop: float = 0.05
    max_parser_reach_rate_increase: float = 0.05


DEFAULT_THRESHOLDS = RegressionThresholds()


@dataclass(frozen=True)
class RegressionResult:
    is_regression: bool
    reasons: list[str] = field(default_factory=list)
    thresholds_used: dict[str, float] = field(default_factory=dict)


def _thresholds_dict(t: RegressionThresholds) -> dict[str, float]:
    return {
        "max_block_rate_improvement_drop": t.max_block_rate_improvement_drop,
        "max_false_positive_rate_increase": t.max_false_positive_rate_increase,
        "max_false_negative_rate_increase": t.max_false_negative_rate_increase,
        "max_valid_acceptance_rate_drop": t.max_valid_acceptance_rate_drop,
        "max_parser_reach_rate_increase": t.max_parser_reach_rate_increase,
    }


def detect_regressions(
    previous: ControlValidation, latest: ControlValidation, thresholds: RegressionThresholds = DEFAULT_THRESHOLDS
) -> RegressionResult:
    """Compares `latest` against `previous` (the immediately prior
    ControlValidation for the same control, per
    zeroshield.assurance.repository.list_validations) across five
    deterministic rules: verdict deterioration, material effectiveness
    drop, FP/FN degradation, valid-acceptance drop, and parser-exposure
    increase. Any single rule tripping marks the whole result a
    regression."""
    reasons: list[str] = []

    previous_severity = _VERDICT_SEVERITY.get(previous.verdict_label, 2)
    latest_severity = _VERDICT_SEVERITY.get(latest.verdict_label, 2)
    if latest_severity < previous_severity:
        reasons.append(
            f"Verdict deteriorated from '{previous.verdict_label}' to '{latest.verdict_label}'."
        )

    block_rate_drop = previous.block_rate_improvement - latest.block_rate_improvement
    if block_rate_drop > thresholds.max_block_rate_improvement_drop:
        reasons.append(
            f"block_rate_improvement dropped by {block_rate_drop:.3f} "
            f"({previous.block_rate_improvement:.3f} -> {latest.block_rate_improvement:.3f}), "
            f"exceeding the allowed {thresholds.max_block_rate_improvement_drop:.3f}."
        )

    fp_increase = latest.false_positive_rate - previous.false_positive_rate
    if fp_increase > thresholds.max_false_positive_rate_increase:
        reasons.append(
            f"false_positive_rate increased by {fp_increase:.3f} "
            f"({previous.false_positive_rate:.3f} -> {latest.false_positive_rate:.3f}), "
            f"exceeding the allowed {thresholds.max_false_positive_rate_increase:.3f}."
        )

    fn_increase = latest.false_negative_rate - previous.false_negative_rate
    if fn_increase > thresholds.max_false_negative_rate_increase:
        reasons.append(
            f"false_negative_rate increased by {fn_increase:.3f} "
            f"({previous.false_negative_rate:.3f} -> {latest.false_negative_rate:.3f}), "
            f"exceeding the allowed {thresholds.max_false_negative_rate_increase:.3f}."
        )

    valid_acceptance_drop = previous.valid_acceptance_rate - latest.valid_acceptance_rate
    if valid_acceptance_drop > thresholds.max_valid_acceptance_rate_drop:
        reasons.append(
            f"valid_acceptance_rate dropped by {valid_acceptance_drop:.3f} "
            f"({previous.valid_acceptance_rate:.3f} -> {latest.valid_acceptance_rate:.3f}), "
            f"exceeding the allowed {thresholds.max_valid_acceptance_rate_drop:.3f}."
        )

    parser_increase = latest.parser_reach_rate - previous.parser_reach_rate
    if parser_increase > thresholds.max_parser_reach_rate_increase:
        reasons.append(
            f"parser_reach_rate (parser exposure) increased by {parser_increase:.3f} "
            f"({previous.parser_reach_rate:.3f} -> {latest.parser_reach_rate:.3f}), "
            f"exceeding the allowed {thresholds.max_parser_reach_rate_increase:.3f}."
        )

    return RegressionResult(
        is_regression=len(reasons) > 0, reasons=reasons, thresholds_used=_thresholds_dict(thresholds)
    )
