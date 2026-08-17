"""Trace-context propagation (V2 Phase 6, Step 5): a W3C traceparent injected
into a dict carrier (used as RabbitMQ message headers by
zeroshield.api.messaging/zeroshield.intelligence.messaging) must extract back
to a context that continues the same trace - the mechanism that keeps a run
traceable across the RabbitMQ hop from API to worker.
"""

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from zeroshield.observability.tracing import extract_trace_context, inject_trace_context


def test_inject_trace_context_writes_a_traceparent_header_inside_a_span() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")

    with tracer.start_as_current_span("publish"):
        carrier = inject_trace_context({})

    assert "traceparent" in carrier


def test_extract_trace_context_continues_the_same_trace() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")

    with tracer.start_as_current_span("api.publish") as publish_span:
        carrier = inject_trace_context({})
        expected_trace_id = publish_span.get_span_context().trace_id

    parent_context = extract_trace_context(carrier)
    with tracer.start_as_current_span("worker.consume", context=parent_context) as consume_span:
        assert consume_span.get_span_context().trace_id == expected_trace_id


def test_extract_trace_context_with_no_headers_does_not_raise() -> None:
    context = extract_trace_context({})
    assert context is not None
