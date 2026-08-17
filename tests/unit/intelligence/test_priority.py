from datetime import UTC, datetime

import pytest

from zeroshield.intelligence.priority import PriorityWeights, label_for_score, score
from zeroshield.models.enums import ZeroClickRelevance
from zeroshield.models.vulnerability import PriorityLabel, SupportStatus, Vulnerability

NOW = datetime.now(UTC)


def _vuln(**overrides: object) -> Vulnerability:
    base = {"cve_id": "CVE-2024-21762", "first_seen_at": NOW, "last_updated_at": NOW}
    base.update(overrides)
    return Vulnerability(**base)


def test_default_weights_sum_to_100() -> None:
    from zeroshield.intelligence.priority import DEFAULT_WEIGHTS

    assert DEFAULT_WEIGHTS.total_max() == 100.0


@pytest.mark.parametrize(
    ("value", "expected"),
    [(90, PriorityLabel.CRITICAL), (85, PriorityLabel.CRITICAL), (70, PriorityLabel.HIGH),
     (65, PriorityLabel.HIGH), (50, PriorityLabel.MEDIUM), (40, PriorityLabel.MEDIUM), (10, PriorityLabel.LOW)],
)
def test_label_for_score_thresholds(value: float, expected: PriorityLabel) -> None:
    assert label_for_score(value) is expected


def test_high_signal_supported_case_scores_critical() -> None:
    """Mirrors the phase's own worked example: high CVSS + KEV + high EPSS +
    supported domain + no existing validation coverage -> CRITICAL."""
    v = _vuln(cvss_score=9.6, epss_score=0.945, kev_listed=True, zero_click_relevance=ZeroClickRelevance.HIGH)
    result = score(v, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=False)
    assert result.label is PriorityLabel.CRITICAL
    assert result.score > 85
    assert any("CISA KEV" in line for line in result.explanation)
    assert any("CVSS 9.6" in line for line in result.explanation)
    assert any("Total:" in line for line in result.explanation)


def test_no_signal_unsupported_case_scores_low() -> None:
    v = _vuln()
    result = score(v, support_status=SupportStatus.UNSUPPORTED, has_existing_validation_coverage=False)
    assert result.label is PriorityLabel.LOW
    assert result.score == 10.0  # only the no-existing-coverage bonus applies


def test_unsupported_domain_gets_zero_domain_points_regardless_of_zero_click() -> None:
    v = _vuln(zero_click_relevance=ZeroClickRelevance.HIGH)
    result = score(v, support_status=SupportStatus.UNSUPPORTED, has_existing_validation_coverage=False)
    assert any("UNSUPPORTED" in line and "+0.0" in line for line in result.explanation)


def test_partially_supported_gets_half_domain_weight_when_zero_click_high() -> None:
    v_supported = _vuln(zero_click_relevance=ZeroClickRelevance.HIGH)
    v_partial = _vuln(cve_id="CVE-2024-21763", zero_click_relevance=ZeroClickRelevance.HIGH)
    supported = score(v_supported, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=True)
    partial = score(v_partial, support_status=SupportStatus.PARTIALLY_SUPPORTED, has_existing_validation_coverage=True)
    assert partial.score < supported.score


def test_unknown_zero_click_relevance_gets_half_credit_not_zero_or_full() -> None:
    v_unknown = _vuln()
    v_high = _vuln(cve_id="CVE-2024-21763", zero_click_relevance=ZeroClickRelevance.HIGH)
    v_low = _vuln(cve_id="CVE-2024-21764", zero_click_relevance=ZeroClickRelevance.LOW)

    unknown = score(v_unknown, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=True)
    high = score(v_high, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=True)
    low = score(v_low, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=True)
    assert low.score < unknown.score < high.score


def test_existing_coverage_reduces_score() -> None:
    v = _vuln(cvss_score=9.6)
    covered = score(v, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=True)
    uncovered = score(v, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=False)
    assert uncovered.score == pytest.approx(covered.score + 10.0)


def test_missing_cvss_and_epss_contribute_zero_not_error() -> None:
    v = _vuln(kev_listed=True)
    result = score(v, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=False)
    assert any("No CVSS score available" in line for line in result.explanation)
    assert any("No EPSS score available" in line for line in result.explanation)


def test_custom_weights_are_respected_and_adjustable() -> None:
    v = _vuln(cvss_score=10.0)
    custom = PriorityWeights(cvss_max=50.0, epss_max=20.0, kev_flat=15.0, domain_max=10.0, no_coverage_flat=5.0)
    assert custom.total_max() == 100.0
    result = score(v, support_status=SupportStatus.UNSUPPORTED, has_existing_validation_coverage=True, weights=custom)
    assert any("50.0" in line for line in result.explanation)


def test_score_never_exceeds_weights_total_max() -> None:
    v = _vuln(cvss_score=10.0, epss_score=1.0, kev_listed=True, zero_click_relevance=ZeroClickRelevance.HIGH)
    result = score(v, support_status=SupportStatus.SUPPORTED, has_existing_validation_coverage=False)
    assert result.score <= 100.0
