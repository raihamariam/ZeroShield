import pytest
from pydantic import ValidationError

from zeroshield.models import Decision, TestCase, TestCaseCategory


def _valid_test_case_data() -> dict:
    return {
        "case_id": "TC-VPN-001",
        "category": "malformed",
        "input_data": {"path": "/../../etc/passwd", "length": 9999},
        "expected_outcome": "blocked",
        "provenance": "synthetic, derived from CVE-2024-21762 oversized pre-auth field pattern",
        "version": "1.0.0",
    }


def test_valid_test_case_parses() -> None:
    case = TestCase(**_valid_test_case_data())
    assert case.category == TestCaseCategory.MALFORMED
    assert case.expected_outcome == Decision.BLOCKED


def test_invalid_category_rejected() -> None:
    data = _valid_test_case_data()
    data["category"] = "not_a_category"
    with pytest.raises(ValidationError, match="category"):
        TestCase(**data)


def test_test_case_is_immutable() -> None:
    case = TestCase(**_valid_test_case_data())
    with pytest.raises(ValidationError):
        case.case_id = "TC-VPN-002"
