"""OpenTelemetry tracing configuration (V2 Phase 6, Step 5).

FastAPI (`FastAPIInstrumentor.instrument_app`, zeroshield.api.app) is the
trace root - there is no browser- or Next.js-side OpenTelemetry
instrumentation, so a trace does not begin until a request reaches the API.
From there, a run/sync is traceable as one distributed trace across the
process boundaries it crosses on the backend - API -> RabbitMQ -> worker ->
validation -> evidence - by propagating the W3C traceparent header through
the one hop that would otherwise disconnect the trace: the RabbitMQ message
(see inject_trace_context/extract_trace_context, used by
zeroshield.api.messaging.publish_run_job and
zeroshield.worker.main/intelligence_main's consume loops).

request_id (zeroshield.api.observability.RequestContextMiddleware) is a
separate, older correlation mechanism, not an OTel span attribute, and is
generated fresh (server-side UUID4 hex) on every request today - the
middleware *would* reuse an inbound X-Request-ID header if a caller set
one, but apps/web's own fetch calls do not currently set that header, so in
practice this is API-only, not something that actually originates in the
browser yet. It is joined to trace_id/span_id only at the *logging* layer
(zeroshield.observability.logging.JsonFormatter reads both the current span
and this request_id and puts them on the same JSON log line) - a log line
is where the two mechanisms meet, not the trace itself.

No exporter is attached unless one is explicitly requested:
  - OTEL_EXPORTER_OTLP_ENDPOINT set -> spans are sent to that OTLP/HTTP
    collector (Jaeger, Tempo, etc.) - the real deployment path.
  - ZEROSHIELD_TRACING_CONSOLE=1 -> spans are dumped to stdout as JSON - a
    local debugging aid.
  - neither set (the default) -> the TracerProvider still exists and spans
    are still created, but nothing is exported anywhere. This matters in
    practice: it means running the app - or the ~1000-test suite, which
    exercises the instrumented FastAPI app via TestClient thousands of
    times per run - never requires a collector to be reachable and never
    spams stdout/CI logs with span dumps.
"""

import os

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.propagate import extract, inject
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

_configured_service_names: set[str] = set()


def configure_tracing(service_name: str) -> None:
    """Idempotent per service_name - safe to call more than once (module
    import order, or repeated main() calls in tests) without accumulating
    duplicate span processors/exporters."""
    if service_name in _configured_service_names:
        return
    _configured_service_names.add(service_name)

    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: service_name}))

    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")))
    elif os.environ.get("ZEROSHIELD_TRACING_CONSOLE") == "1":
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)


def inject_trace_context(carrier: dict[str, str]) -> dict[str, str]:
    """Writes the current span's W3C traceparent into carrier in place, and
    returns it - used to build RabbitMQ message headers so the worker
    continues the same trace instead of starting a disconnected one."""
    inject(carrier)
    return carrier


def extract_trace_context(carrier: dict[str, str]) -> Context:
    return extract(carrier)
