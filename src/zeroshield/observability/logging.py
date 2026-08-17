"""Structured JSON logging (V2 Phase 6, Step 5): one JSON object per line on
stdout, so a log aggregator can index every field without a parsing regex,
and so a request_id/trace_id printed here can be grepped and cross-referenced
against an audit_events row (zeroshield.audit) or a trace in the configured
OTel backend (zeroshield.observability.tracing) for the same operation.

Deliberately just a logging.Formatter, not a logging framework replacement -
every existing `logging.getLogger(...)`/`logger.info(...)` call in this
codebase keeps working unchanged; only the output *shape* changes.
"""

import json
import logging
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from opentelemetry import trace

_RESERVED_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}

# Set by zeroshield.api.observability.RequestContextMiddleware for the
# duration of one HTTP request, so every log line emitted while handling it -
# from route handlers down through repository/service code, with no explicit
# `extra=` needed at each call site - carries the same request_id as the
# X-Request-ID response header and any audit_events row for that request.
request_id_var: ContextVar[str | None] = ContextVar("zeroshield_request_id", default=None)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = getattr(record, "request_id", None) or request_id_var.get()
        if request_id is not None:
            payload["request_id"] = request_id

        span = trace.get_current_span()
        span_context = span.get_span_context()
        if span_context.is_valid:
            payload["trace_id"] = format(span_context.trace_id, "032x")
            payload["span_id"] = format(span_context.span_id, "016x")

        # Any extra=... fields a caller passed to the log call, beyond the
        # standard LogRecord attributes - e.g. job_id, experiment_id.
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_ATTRS and key not in payload:
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_json_logging(level: int = logging.INFO) -> None:
    """Replaces the root logger's handlers with a single JSON-formatted
    stream handler - call once at process startup (API/worker main()), in
    place of logging.basicConfig(level=...)."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
