from datetime import UTC, datetime

from zeroshield.intelligence.candidates import classify_domain, generate_candidate
from zeroshield.models.enums import Domain
from zeroshield.models.vulnerability import SupportStatus, Vulnerability

NOW = datetime.now(UTC)


def _vuln(**overrides: object) -> Vulnerability:
    base = {"cve_id": "CVE-2024-21762", "first_seen_at": NOW, "last_updated_at": NOW}
    base.update(overrides)
    return Vulnerability(**base)


def test_classify_vpn_product_term_is_supported() -> None:
    v = _vuln(vendor="Fortinet", description="FortiOS SSL VPN out-of-bound write")
    result = classify_domain(v)
    assert result.domain is Domain.VPN
    assert result.support_status is SupportStatus.SUPPORTED


def test_classify_telecom_product_term_is_supported() -> None:
    v = _vuln(vendor="Cisco", description="SIP session handling flaw in carrier infrastructure")
    result = classify_domain(v)
    assert result.domain is Domain.TELECOM
    assert result.support_status is SupportStatus.SUPPORTED


def test_classify_weak_single_term_is_partially_supported() -> None:
    v = _vuln(vendor="Acme", description="generic vpn-adjacent issue with no strong product match")
    result = classify_domain(v)
    assert result.support_status is SupportStatus.PARTIALLY_SUPPORTED


def test_classify_no_match_is_unsupported() -> None:
    v = _vuln(vendor="SomeCMS", description="SQL injection in a web CMS plugin")
    result = classify_domain(v)
    assert result.support_status is SupportStatus.UNSUPPORTED
    assert result.domain is None


def test_classify_cross_domain_ambiguous_match_is_partially_supported_no_domain() -> None:
    v = _vuln(vendor="Acme", description="SIP over VPN gateway issue")
    result = classify_domain(v)
    assert result.support_status is SupportStatus.PARTIALLY_SUPPORTED
    assert result.domain is None


def test_generate_candidate_returns_none_for_unsupported() -> None:
    v = _vuln(vendor="SomeCMS", description="SQL injection in a web CMS plugin")
    assert generate_candidate(v, experiment_ids_by_cve={}) is None


def test_generate_candidate_returns_candidate_for_supported() -> None:
    v = _vuln(vendor="Fortinet", description="FortiOS SSL VPN issue", cvss_score=9.6, kev_listed=True)
    candidate = generate_candidate(v, experiment_ids_by_cve={"CVE-2024-21762": ["ZC-VPN-EXP-001"]})
    assert candidate is not None
    assert candidate.domain is Domain.VPN
    assert candidate.support_status is SupportStatus.SUPPORTED
    assert candidate.existing_experiment_ids == ["ZC-VPN-EXP-001"]
    assert len(candidate.explanation) >= 1


def test_generate_candidate_no_existing_coverage_scores_higher() -> None:
    v = _vuln(vendor="Fortinet", description="FortiOS SSL VPN issue", cvss_score=9.6)
    covered = generate_candidate(v, experiment_ids_by_cve={"CVE-2024-21762": ["ZC-VPN-EXP-001"]})
    uncovered = generate_candidate(v, experiment_ids_by_cve={})
    assert uncovered.priority_score > covered.priority_score


def test_generate_candidate_uses_injected_clock() -> None:
    fixed = datetime(2026, 1, 1, tzinfo=UTC)
    v = _vuln(vendor="Fortinet", description="FortiOS SSL VPN issue")
    candidate = generate_candidate(v, experiment_ids_by_cve={}, clock=lambda: fixed)
    assert candidate.generated_at == fixed
