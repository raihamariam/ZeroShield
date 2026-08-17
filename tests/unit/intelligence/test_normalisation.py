import pytest

from zeroshield.intelligence.connectors.base import RawIntelligenceRecord
from zeroshield.intelligence.normalisation import (
    NormalisationError,
    normalise,
    normalise_vendor_advisory,
)
from zeroshield.models.vulnerability import VulnerabilitySourceName


def _nvd_record(**overrides: object) -> RawIntelligenceRecord:
    raw = {
        "id": "CVE-2024-21762",
        "sourceIdentifier": "psirt@fortinet.com",
        "published": "2024-02-08T00:00:00.000",
        "lastModified": "2024-02-09T15:00:00.000",
        "descriptions": [{"lang": "en", "value": "FortiOS SSL VPN out-of-bound write."}],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.6, "vectorString": "CVSS:3.1/AV:N", "version": "3.1"}}]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
        "references": [{"url": "https://www.fortiguard.com/psirt/FG-IR-24-015"}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "7.0.0",
                                "versionEndExcluding": "7.0.14",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    raw.update(overrides)
    return RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id=raw["id"], raw=raw)


def test_normalise_nvd_extracts_all_fields() -> None:
    result = normalise(_nvd_record())
    assert result.cve_id == "CVE-2024-21762"
    assert result.cvss_score == 9.6
    assert result.cvss_version == "3.1"
    assert result.cwe_ids == ["CWE-787"]
    assert result.vendor == "fortinet"
    assert result.products == [("fortinet", "fortios", ">=7.0.0 <7.0.14")]
    assert "fortiguard.com" in result.references[0]
    assert result.description.startswith("FortiOS")


def test_normalise_nvd_prefers_v31_over_v30_and_v2() -> None:
    raw = _nvd_record().raw
    raw["metrics"]["cvssMetricV30"] = [{"cvssData": {"baseScore": 1.0, "vectorString": "old", "version": "3.0"}}]
    result = normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="x", raw=raw))
    assert result.cvss_score == 9.6  # v3.1 wins


def test_normalise_nvd_falls_back_to_v2_when_no_v3() -> None:
    raw = _nvd_record().raw
    del raw["metrics"]["cvssMetricV31"]
    raw["metrics"]["cvssMetricV2"] = [{"cvssData": {"baseScore": 5.0, "vectorString": "old", "version": "2.0"}}]
    result = normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="x", raw=raw))
    assert result.cvss_score == 5.0
    assert result.cvss_version == "2.0"


def test_normalise_nvd_missing_cve_id_raises() -> None:
    with pytest.raises(NormalisationError, match="missing or malformed"):
        normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="", raw={"id": None}))


def test_normalise_nvd_malformed_cve_id_raises() -> None:
    with pytest.raises(NormalisationError):
        normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="x", raw={"id": "not-a-cve"}))


def test_normalise_nvd_missing_optional_fields_yields_none_not_error() -> None:
    """Partial upstream data (Step 12: 'partial data') must never crash normalisation -
    only a missing CVE ID is fatal."""
    raw = {"id": "CVE-2024-00001"}
    result = normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="x", raw=raw))
    assert result.cve_id == "CVE-2024-00001"
    assert result.cvss_score is None
    assert result.description is None
    assert result.cwe_ids == []


def test_normalise_cisa_kev_extracts_fields() -> None:
    raw = {
        "cveID": "CVE-2024-21762",
        "vendorProject": "Fortinet",
        "product": "FortiOS",
        "dateAdded": "2024-02-09",
        "dueDate": "2024-02-16",
        "shortDescription": "desc",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762 more text",
        "cwes": ["CWE-787"],
    }
    result = normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.CISA_KEV, external_id="x", raw=raw))
    assert result.kev_listed is True
    assert result.kev_date_added.isoformat() == "2024-02-09"
    assert result.kev_due_date.isoformat() == "2024-02-16"
    assert result.vendor == "Fortinet"
    assert result.products == [("Fortinet", "FortiOS", None)]
    assert result.references == ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"]


def test_normalise_epss_extracts_and_converts_types() -> None:
    raw = {"cve": "CVE-2024-21762", "epss": "0.94500", "percentile": "0.99120", "date": "2026-08-17"}
    result = normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.EPSS, external_id="x", raw=raw))
    assert result.epss_score == pytest.approx(0.945)
    assert result.epss_percentile == pytest.approx(0.9912)
    assert result.epss_date.isoformat() == "2026-08-17"


def test_normalise_epss_malformed_numeric_fields_yield_none() -> None:
    raw = {"cve": "CVE-2024-21762", "epss": "not-a-number", "percentile": None, "date": "bad-date"}
    result = normalise(RawIntelligenceRecord(source=VulnerabilitySourceName.EPSS, external_id="x", raw=raw))
    assert result.epss_score is None
    assert result.epss_percentile is None
    assert result.epss_date is None


def test_normalise_unregistered_source_raises() -> None:
    with pytest.raises(NormalisationError, match="no normaliser registered"):
        normalise(
            RawIntelligenceRecord(source=VulnerabilitySourceName.GITHUB_ADVISORY, external_id="x", raw={})
        )


def test_normalise_vendor_advisory_links_cve_and_extracts_cvss() -> None:
    raw = {
        "ghsa_id": "GHSA-xxxx",
        "cve_id": "CVE-2024-21762",
        "summary": "sum",
        "description": "desc",
        "severity": "critical",
        "cvss_severities": {"cvss_v3": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N"}},
        "cwes": [{"cwe_id": "CWE-787"}],
        "published_at": "2024-02-08T00:00:00Z",
        "updated_at": "2024-02-09T00:00:00Z",
        "references": ["https://example.com"],
    }
    record = RawIntelligenceRecord(source=VulnerabilitySourceName.GITHUB_ADVISORY, external_id="GHSA-xxxx", raw=raw)
    advisory, contribution = normalise_vendor_advisory(record)
    assert advisory.advisory_id == "GHSA-xxxx"
    assert advisory.cve_id == "CVE-2024-21762"
    assert contribution is not None
    assert contribution.cve_id == "CVE-2024-21762"
    assert contribution.cvss_score == 9.8


def test_normalise_vendor_advisory_without_cve_returns_advisory_only() -> None:
    raw = {"ghsa_id": "GHSA-yyyy", "cve_id": None, "summary": "sum"}
    record = RawIntelligenceRecord(source=VulnerabilitySourceName.GITHUB_ADVISORY, external_id="GHSA-yyyy", raw=raw)
    advisory, contribution = normalise_vendor_advisory(record)
    assert advisory.advisory_id == "GHSA-yyyy"
    assert advisory.cve_id is None
    assert contribution is None


def test_normalise_vendor_advisory_wrong_source_raises() -> None:
    with pytest.raises(NormalisationError, match="not a recognised vendor advisory source"):
        normalise_vendor_advisory(
            RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="x", raw={})
        )
