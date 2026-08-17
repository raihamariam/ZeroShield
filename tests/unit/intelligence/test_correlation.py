"""Step 4: deterministic CVE correlation - every feature independently, plus
the ranking/filtering helper."""

from datetime import UTC, datetime

from zeroshield.intelligence.correlation import CAVEAT, correlate, rank_correlations
from zeroshield.models.enums import Domain
from zeroshield.models.vulnerability import Vulnerability

NOW = datetime.now(UTC)


def _vuln(cve_id: str, **overrides: object) -> Vulnerability:
    base = {"cve_id": cve_id, "first_seen_at": NOW, "last_updated_at": NOW}
    base.update(overrides)
    return Vulnerability(**base)


def test_identical_vulnerabilities_score_highly() -> None:
    a = _vuln("CVE-2024-00001", vendor="Fortinet", domain_guess=Domain.VPN, cwe_ids=["CWE-787"], description="oob write")
    b = _vuln("CVE-2024-00002", vendor="Fortinet", domain_guess=Domain.VPN, cwe_ids=["CWE-787"], description="oob write")
    result = correlate(a, b)
    assert result.score > 60.0
    assert CAVEAT in result.explanation[-1]


def test_unrelated_vulnerabilities_score_low() -> None:
    a = _vuln("CVE-2024-00001", vendor="Fortinet", domain_guess=Domain.VPN, cwe_ids=["CWE-787"], description="oob write")
    b = _vuln("CVE-2024-00002", vendor="Acme", domain_guess=Domain.TELECOM, cwe_ids=["CWE-89"], description="sql injection")
    result = correlate(a, b)
    assert result.score < 15.0


def test_vendor_match_is_case_insensitive() -> None:
    a = _vuln("CVE-2024-00001", vendor="Fortinet")
    b = _vuln("CVE-2024-00002", vendor="FORTINET")
    result = correlate(a, b)
    assert any("Same vendor" in e for e in result.explanation)


def test_no_cwe_data_contributes_zero_not_a_crash() -> None:
    a = _vuln("CVE-2024-00001")
    b = _vuln("CVE-2024-00002")
    result = correlate(a, b)
    assert result.score >= 0.0


def test_shared_experiment_coverage_is_reported() -> None:
    a = _vuln("CVE-2024-00001")
    b = _vuln("CVE-2024-00002")
    result = correlate(a, b, subject_experiment_ids=["ZC-VPN-EXP-001"], candidate_experiment_ids=["ZC-VPN-EXP-001"])
    assert result.shared_experiment_ids == ["ZC-VPN-EXP-001"]
    assert any("shared experiment" in e for e in result.explanation)


def test_rank_correlations_excludes_subject_and_sorts_descending() -> None:
    subject = _vuln("CVE-2024-00001", vendor="Fortinet", cwe_ids=["CWE-787"])
    close = _vuln("CVE-2024-00002", vendor="Fortinet", cwe_ids=["CWE-787"])
    far = _vuln("CVE-2024-00003", vendor="Acme", cwe_ids=["CWE-89"])
    self_copy = _vuln("CVE-2024-00001")

    ranked = rank_correlations(subject, [close, far, self_copy])
    assert [r.cve_id for r in ranked] == ["CVE-2024-00002", "CVE-2024-00003"]
    assert ranked[0].score >= ranked[1].score


def test_rank_correlations_respects_min_score_and_limit() -> None:
    subject = _vuln("CVE-2024-00001", vendor="Fortinet", cwe_ids=["CWE-787"])
    candidates = [_vuln(f"CVE-2024-{i:05d}", vendor="Acme") for i in range(2, 6)]
    ranked = rank_correlations(subject, candidates, min_score=1000.0)
    assert ranked == []
    ranked_limited = rank_correlations(subject, candidates, min_score=0.0, limit=2)
    assert len(ranked_limited) == 2
