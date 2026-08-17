from datetime import UTC, datetime

from zeroshield.intelligence.dedup import merge
from zeroshield.intelligence.normalisation import NormalisedContribution
from zeroshield.models.enums import ZeroClickRelevance
from zeroshield.models.vulnerability import VulnerabilitySourceName

FIXED = datetime(2026, 8, 17, tzinfo=UTC)


def _contribution(source: VulnerabilitySourceName, **overrides: object) -> NormalisedContribution:
    base = {
        "cve_id": "CVE-2024-21762",
        "source": source,
        "source_identifier": None,
        "description": None,
        "published_at": None,
        "last_modified_at": None,
        "cvss_score": None,
        "cvss_vector": None,
        "cvss_version": None,
        "epss_score": None,
        "epss_percentile": None,
        "epss_date": None,
        "kev_listed": None,
        "kev_date_added": None,
        "kev_due_date": None,
        "kev_known_ransomware": None,
    }
    base.update(overrides)
    return NormalisedContribution(**base)


def test_merge_first_contribution_creates_new_vulnerability() -> None:
    contribution = _contribution(VulnerabilitySourceName.NVD, description="NVD desc", cvss_score=9.6)
    result = merge(None, contribution, clock=lambda: FIXED)
    assert result.is_new is True
    assert result.vulnerability.description == "NVD desc"
    assert result.vulnerability.cvss_score == 9.6
    assert result.vulnerability.first_seen_at == FIXED
    assert len(result.history) == 2  # description, cvss_score


def test_merge_nvd_description_not_overwritten_by_lower_priority_source() -> None:
    nvd = merge(None, _contribution(VulnerabilitySourceName.NVD, description="NVD desc"), clock=lambda: FIXED)
    kev = merge(
        nvd.vulnerability,
        _contribution(VulnerabilitySourceName.CISA_KEV, description="KEV desc", kev_listed=True),
        clock=lambda: FIXED,
    )
    assert kev.vulnerability.description == "NVD desc"  # KEV's description never wins
    assert kev.vulnerability.kev_listed is True
    assert kev.is_new is False


def test_merge_epss_field_only_ever_comes_from_epss() -> None:
    nvd = merge(None, _contribution(VulnerabilitySourceName.NVD, cvss_score=9.6), clock=lambda: FIXED)
    epss = merge(
        nvd.vulnerability, _contribution(VulnerabilitySourceName.EPSS, epss_score=0.9), clock=lambda: FIXED
    )
    assert epss.vulnerability.cvss_score == 9.6  # untouched
    assert epss.vulnerability.epss_score == 0.9
    assert [h.field for h in epss.history] == ["epss_score"]


def test_merge_unions_cwe_ids_references_and_sources() -> None:
    nvd = merge(
        None,
        _contribution(VulnerabilitySourceName.NVD, cwe_ids=["CWE-787"], references=["https://a.example"]),
        clock=lambda: FIXED,
    )
    kev = merge(
        nvd.vulnerability,
        _contribution(
            VulnerabilitySourceName.CISA_KEV, kev_listed=True, cwe_ids=["CWE-787", "CWE-20"],
            references=["https://b.example"],
        ),
        clock=lambda: FIXED,
    )
    assert set(kev.vulnerability.cwe_ids) == {"CWE-787", "CWE-20"}
    assert {str(r) for r in kev.vulnerability.references} == {"https://a.example/", "https://b.example/"}
    assert set(kev.vulnerability.sources) == {VulnerabilitySourceName.NVD, VulnerabilitySourceName.CISA_KEV}


def test_merge_published_at_keeps_earliest_last_modified_at_keeps_latest() -> None:
    earlier = datetime(2024, 1, 1, tzinfo=UTC)
    later = datetime(2024, 6, 1, tzinfo=UTC)
    nvd = merge(
        None,
        _contribution(VulnerabilitySourceName.NVD, published_at=later, last_modified_at=earlier),
        clock=lambda: FIXED,
    )
    manual = merge(
        nvd.vulnerability,
        _contribution(VulnerabilitySourceName.MANUAL_IMPORT, published_at=earlier, last_modified_at=later),
        clock=lambda: FIXED,
    )
    assert manual.vulnerability.published_at == earlier
    assert manual.vulnerability.last_modified_at == later


def test_merge_zero_click_relevance_only_recorded_when_present() -> None:
    contribution = _contribution(
        VulnerabilitySourceName.MANUAL_IMPORT, zero_click_relevance=ZeroClickRelevance.HIGH
    )
    result = merge(None, contribution, clock=lambda: FIXED)
    assert result.vulnerability.zero_click_relevance is ZeroClickRelevance.HIGH

    unchanged = merge(
        result.vulnerability, _contribution(VulnerabilitySourceName.EPSS, epss_score=0.5), clock=lambda: FIXED
    )
    assert unchanged.vulnerability.zero_click_relevance is ZeroClickRelevance.HIGH  # not clobbered by EPSS


def test_merge_no_op_contribution_produces_no_history() -> None:
    nvd = merge(None, _contribution(VulnerabilitySourceName.NVD, cvss_score=9.6), clock=lambda: FIXED)
    repeat = merge(nvd.vulnerability, _contribution(VulnerabilitySourceName.NVD, cvss_score=9.6), clock=lambda: FIXED)
    assert repeat.history == []


def test_merge_first_seen_at_stable_across_updates() -> None:
    first = merge(None, _contribution(VulnerabilitySourceName.NVD), clock=lambda: FIXED)
    later_time = datetime(2026, 9, 1, tzinfo=UTC)
    second = merge(
        first.vulnerability, _contribution(VulnerabilitySourceName.EPSS, epss_score=0.5), clock=lambda: later_time
    )
    assert second.vulnerability.first_seen_at == FIXED
    assert second.vulnerability.last_updated_at == later_time
