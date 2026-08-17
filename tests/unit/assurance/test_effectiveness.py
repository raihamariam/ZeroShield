"""Step 9: aggregation must never blend validations across control
versions - only within the current version."""

from datetime import UTC, datetime, timedelta

from zeroshield.assurance.effectiveness import summarise_effectiveness
from zeroshield.assurance.models import ControlValidation

NOW = datetime.now(UTC)


def _validation(version_id: str, *, block_rate: float, verdict: str, days_ago: int) -> ControlValidation:
    return ControlValidation(
        validation_id=f"VAL-{version_id}-{days_ago}", control_id="C", version_id=version_id,
        experiment_id="ZC-VPN-EXP-001", baseline_run_id="RUN-1", mitigation_run_id="RUN-2", total_cases=10,
        block_rate_improvement=block_rate, false_positive_rate=0.0, false_negative_rate=0.0,
        valid_acceptance_rate=1.0, parser_reach_rate=0.0, latency_overhead_ms=1.0, verdict_label=verdict,
        validated_at=NOW - timedelta(days=days_ago),
    )


def test_no_validations_returns_none() -> None:
    assert summarise_effectiveness("C", []) is None


def test_aggregates_only_within_current_version() -> None:
    validations = [
        _validation("v1", block_rate=0.9, verdict="effective", days_ago=30),
        _validation("v1", block_rate=0.8, verdict="effective", days_ago=20),
        _validation("v2", block_rate=0.2, verdict="ineffective", days_ago=1),
    ]
    summary = summarise_effectiveness("C", validations)
    assert summary is not None
    assert summary.current_version_id == "v2"
    # Only the v2 validation counts toward the current-version mean - the two
    # v1 validations (0.9, 0.8) must never be blended in with v2's 0.2.
    assert summary.validation_count_current_version == 1
    assert summary.mean_block_rate_improvement_current_version == 0.2
    assert summary.total_validation_count == 3


def test_latest_and_previous_verdict_are_the_two_most_recent_overall() -> None:
    validations = [
        _validation("v1", block_rate=0.9, verdict="effective", days_ago=10),
        _validation("v2", block_rate=0.2, verdict="partially_effective", days_ago=1),
    ]
    summary = summarise_effectiveness("C", validations)
    assert summary is not None
    assert summary.latest_verdict == "partially_effective"
    assert summary.previous_verdict == "effective"


def test_single_validation_has_no_previous_verdict() -> None:
    summary = summarise_effectiveness("C", [_validation("v1", block_rate=0.5, verdict="effective", days_ago=1)])
    assert summary is not None
    assert summary.previous_verdict is None
