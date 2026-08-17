"""JsonFormatter (V2 Phase 6, Step 5): every log line is one JSON object with
timestamp/level/logger/message, plus request_id when a request is in flight
and trace_id/span_id when a span is active - never raw text that would need
a parsing regex in a log aggregator.
"""

import json
import logging

from zeroshield.observability.logging import JsonFormatter, request_id_var


def _make_record(msg: str = "hello", level: int = logging.INFO, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name="zeroshield.test", level=level, pathname=__file__, lineno=1, msg=msg, args=(), exc_info=None
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_format_produces_valid_json_with_core_fields() -> None:
    payload = json.loads(JsonFormatter().format(_make_record("hello world")))
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "zeroshield.test"
    assert "timestamp" in payload


def test_format_includes_request_id_from_contextvar() -> None:
    token = request_id_var.set("req-abc123")
    try:
        payload = json.loads(JsonFormatter().format(_make_record()))
    finally:
        request_id_var.reset(token)
    assert payload["request_id"] == "req-abc123"


def test_format_omits_request_id_when_none_is_set() -> None:
    payload = json.loads(JsonFormatter().format(_make_record()))
    assert "request_id" not in payload


def test_format_includes_extra_fields_not_reserved_by_logrecord() -> None:
    payload = json.loads(JsonFormatter().format(_make_record(job_id="JOB-1", experiment_id="ZC-VPN-EXP-001")))
    assert payload["job_id"] == "JOB-1"
    assert payload["experiment_id"] == "ZC-VPN-EXP-001"


def test_format_includes_formatted_exception_text() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = _make_record("failed")
        record.exc_info = sys.exc_info()
    payload = json.loads(JsonFormatter().format(record))
    assert "boom" in payload["exception"]
