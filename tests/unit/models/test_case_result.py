import pytest
from pydantic import ValidationError

from zeroshield.models import CaseResult, Decision


def _base_result_data() -> dict:
    return {
        "run_id": "RUN-001",
        "case_id": "TC-VPN-001",
        "decision": "blocked",
        "parser_reached": False,
        "errored": False,
        "logged": True,
        "latency_ms": 3.2,
    }


def test_valid_case_result_without_error_parses() -> None:
    result = CaseResult(**_base_result_data())
    assert result.decision == Decision.BLOCKED
    assert result.error_message is None


def test_valid_case_result_with_error_parses() -> None:
    data = _base_result_data()
    data["errored"] = True
    data["error_message"] = "parser raised an unexpected exception"
    result = CaseResult(**data)
    assert result.errored is True


def test_errored_without_message_rejected() -> None:
    data = _base_result_data()
    data["errored"] = True
    with pytest.raises(ValidationError, match="error_message is required"):
        CaseResult(**data)


def test_not_errored_with_message_rejected() -> None:
    data = _base_result_data()
    data["error_message"] = "should not be here"
    with pytest.raises(ValidationError, match="must be None"):
        CaseResult(**data)


def test_negative_latency_rejected() -> None:
    data = _base_result_data()
    data["latency_ms"] = -1.0
    with pytest.raises(ValidationError, match="latency_ms"):
        CaseResult(**data)
