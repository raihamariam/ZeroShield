import pytest
from pydantic import ValidationError

from zeroshield.models import TestSet


def _valid_case(case_id: str) -> dict:
    return {
        "case_id": case_id,
        "category": "valid",
        "input_data": {"method": "GET", "path": "/remote/login"},
        "expected_outcome": "accepted",
        "provenance": "synthetic",
        "version": "1.0.0",
    }


def test_valid_test_set_parses() -> None:
    test_set = TestSet(
        test_set_id="vpn-pre-auth-request-v1",
        version="1.0.0",
        domain="VPN",
        cases=[_valid_case("TC-001"), _valid_case("TC-002")],
    )
    assert len(test_set.cases) == 2


def test_empty_cases_rejected() -> None:
    with pytest.raises(ValidationError, match="cases"):
        TestSet(test_set_id="vpn-pre-auth-request-v1", version="1.0.0", domain="VPN", cases=[])


def test_duplicate_case_ids_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate case_id"):
        TestSet(
            test_set_id="vpn-pre-auth-request-v1",
            version="1.0.0",
            domain="VPN",
            cases=[_valid_case("TC-001"), _valid_case("TC-001")],
        )


def test_test_set_is_immutable() -> None:
    test_set = TestSet(
        test_set_id="vpn-pre-auth-request-v1",
        version="1.0.0",
        domain="VPN",
        cases=[_valid_case("TC-001")],
    )
    with pytest.raises(ValidationError):
        test_set.version = "2.0.0"
