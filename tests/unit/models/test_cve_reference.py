import pytest
from pydantic import ValidationError

from zeroshield.models import CVEReference


def test_valid_cve_reference_parses(valid_cve_reference_data: dict) -> None:
    ref = CVEReference(**valid_cve_reference_data)
    assert ref.cve_id == "CVE-2024-21762"
    assert ref.cisa_kev is True


def test_invalid_cve_id_pattern_rejected(valid_cve_reference_data: dict) -> None:
    valid_cve_reference_data["cve_id"] = "not-a-cve-id"
    with pytest.raises(ValidationError, match="cve_id"):
        CVEReference(**valid_cve_reference_data)


def test_cvss_score_out_of_range_rejected(valid_cve_reference_data: dict) -> None:
    valid_cve_reference_data["cvss_score"] = 11.0
    with pytest.raises(ValidationError, match="cvss_score"):
        CVEReference(**valid_cve_reference_data)


def test_epss_score_out_of_range_rejected(valid_cve_reference_data: dict) -> None:
    valid_cve_reference_data["epss_score"] = 1.5
    with pytest.raises(ValidationError, match="epss_score"):
        CVEReference(**valid_cve_reference_data)


def test_empty_source_urls_rejected(valid_cve_reference_data: dict) -> None:
    valid_cve_reference_data["source_urls"] = []
    with pytest.raises(ValidationError, match="source_urls"):
        CVEReference(**valid_cve_reference_data)


def test_cve_reference_is_immutable(valid_cve_reference_data: dict) -> None:
    ref = CVEReference(**valid_cve_reference_data)
    with pytest.raises(ValidationError):
        ref.cvss_score = 5.0
