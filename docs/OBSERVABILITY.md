# ZeroShield Observability Reference (V2 Phase 6, Step 5)

Operational observability - metrics, structured logs, and distributed
traces - for the running system. None of this is a substitute for, or read
by, the scientific evidence (`EvidenceManifest`/`ComparisonReport` under
`results/`) or the audit trail (`docs/SECURITY.md` §4) - it describes how
the *system* is behaving, not an experiment's findings or who did what.

## 1. Prometheus metrics (`zeroshield.observability.metrics`)

Exposed at `GET /metrics` (API, port 8000) and via a small metrics HTTP
server each worker process starts on its own port:

| Metric | Type | Labels | Exposed by |
|---|---|---|---|
| `zeroshield_api_requests_total` | Counter | `method`, `path`, `status_code` | API |
| `zeroshield_api_request_duration_seconds` | Histogram | `method`, `path` | API |
| `zeroshield_experiment_runs_submitted_total` | Counter | `experiment_id`, `execution_context` | API |
| `zeroshield_worker_jobs_processed_total` | Counter | `status` | worker (`:9200`) |
| `zeroshield_worker_job_duration_seconds` | Histogram | - | worker (`:9200`) |
| `zeroshield_intelligence_syncs_total` | Counter | `source`, `status` | intelligence-worker (`:9201`) |
| `zeroshield_ai_requests_total` | Counter | `outcome` (`success`/`unavailable`/`invalid_response`) | API (recorded inside `ResearchAnalystService._generate`, the one choke point every AI schema call passes through) |

`path` uses the matched route *template* (e.g. `/experiments/{experiment_id}`),
never the raw resolved path - using the raw path would give every distinct
`experiment_id`, or worse every arbitrary probed 404 path, its own label
combination (an unbounded-cardinality footgun). Unmatched routes are
grouped under `"unmatched"`.

The intelligence-worker's metrics server (`INTELLIGENCE_WORKER_METRICS_PORT`,
default `9201`) is new in Phase 6 - previously only the run-job worker
exposed Prometheus metrics.

### Grafana

`monitoring/grafana/provisioning/dashboards/zeroshield.json`, auto-provisioned,
no manual clicking required. Seven panels: API request rate, worker job
outcomes, worker average job duration, experiment runs submitted, **API
request latency (p95)**, **intelligence syncs (total)**, and **AI Research
Analyst requests by outcome** (bold = added in Phase 6). Grafana at
`http://localhost:3000` (`docker compose up`), pre-wired to the Prometheus
datasource.

## 2. Structured JSON logging (`zeroshield.observability.logging`)

`configure_json_logging()` replaces the root logger's handlers with a
`JsonFormatter` - one JSON object per line on stdout - called once at API
import time (`zeroshield.api.app`) and at worker/intelligence-worker
`main()` startup. Every field a `logging.Formatter` would print, plus:

- `request_id` - present on every API log line emitted while handling one
  HTTP request, via a `contextvars.ContextVar` set by
  `RequestContextMiddleware` (`zeroshield.api.observability`) for the
  duration of that request, with no `extra=` needed at each call site. The
  same ID is echoed on the `X-Request-ID` response header and stamped on
  any audit row written during that request.
- `trace_id`/`span_id` - present whenever a span is active (see below),
  formatted as the standard 32/16-hex-digit W3C identifiers - correlates a
  log line directly to a trace in whatever OTLP backend is configured.
- any `extra=` fields a caller passed to the log call (e.g. `job_id`).

This is a formatter, not a new logging framework - every existing
`logging.getLogger(...)`/`logger.info(...)` call keeps working unchanged;
only the output *shape* changed.

## 3. Distributed tracing (`zeroshield.observability.tracing`)

OpenTelemetry, with a deliberate default: **no exporter is attached unless
one is explicitly requested.**

- `OTEL_EXPORTER_OTLP_ENDPOINT` set -> spans export to that OTLP/HTTP
  collector (Jaeger, Tempo, etc.) - the real deployment path.
- `ZEROSHIELD_TRACING_CONSOLE=1` -> spans print to stdout as JSON - a local
  debugging aid.
- **Neither set (the default)**: the `TracerProvider` still exists and
  spans are still created (and still carry `request_id` via the JSON log
  correlation above), but nothing is exported anywhere. This matters
  concretely: it means running the app, or the ~1000-test suite (which
  exercises the FastAPI app via `TestClient` thousands of times per run),
  never requires a collector to be reachable and never spams stdout/CI logs
  with span dumps.

### What is traced

**FastAPI is the trace root - there is no browser- or Next.js-side
OpenTelemetry instrumentation.** A trace does not begin until a request
actually reaches the API; a browser click and the Next.js Server Component
fetch that follows it are both outside any trace. `request_id` (§2 above)
is a *different, older* correlation mechanism (a plain `X-Request-ID`
header, not an OTel trace) and it is currently API-only in practice too -
`RequestContextMiddleware` would reuse an inbound header if a caller set
one, but `apps/web`'s own fetch calls do not currently set it, so today
every `request_id` is generated fresh server-side, the same as trace
spans. The two are only joined together at the logging layer (§2), not as
a single distributed trace, and neither one currently starts in the
browser.

From the API onward: `FastAPIInstrumentor.instrument_app(app)` wraps the
ASGI app directly (not `app.add_middleware`), so its span is the outermost
one on every API request.

- **API -> RabbitMQ**: `zeroshield.api.messaging.publish_run_job` and
  `zeroshield.intelligence.messaging.publish_sync_job` inject the current
  span's W3C `traceparent` into the AMQP message headers
  (`inject_trace_context`).
- **RabbitMQ -> worker**: `zeroshield.worker.main`/`intelligence_main`'s
  consume callback extracts that header (`extract_trace_context`) and opens
  a `CONSUMER`-kind span (`worker.process_run_job` /
  `intelligence_worker.run_sync`) as its child, tagged with
  `zeroshield.job_id`/`zeroshield.sync_id` - so one run or one sync is a
  single distributed trace from the moment the API accepts the request
  through to the worker finishing the job, not two disconnected traces
  either side of the queue.

Extending this to a genuine browser-to-worker trace would mean adding the
OpenTelemetry Web SDK to `apps/web` and propagating `traceparent` through
its own `fetch()` calls to the API - not implemented, and not planned
unless a real debugging need for browser-side spans specifically emerges
(see [`docs/FUTURE_OPPORTUNITIES.md`](FUTURE_OPPORTUNITIES.md)).

A missing/malformed header (e.g. an older queued message from before this
was added) just produces a fresh root span on the worker side - never an
error.

## 4. Why nothing here is required infrastructure

Every piece above degrades gracefully to "on, but inert" with zero extra
configuration - no Jaeger/Tempo/Grafana-Loki has to be running for the app,
or the test suite, to work. Prometheus/Grafana in `docker compose up` are
the only pieces that need anything running to actually *view* this data;
everything else (JSON logs, in-process spans) is available the moment the
process starts.
