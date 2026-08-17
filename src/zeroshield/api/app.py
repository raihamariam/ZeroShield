"""ZeroShield REST API (Milestones 19-23).

A thin FastAPI interface layer over the existing ZeroShield Core, via
zeroshield.services.experiment_service. No safety, strategy, orchestration,
or metric logic is implemented in this package - see errors.py for the
central exception -> HTTP response mapping and dependencies.py for how
experiment_id/job_id path parameters are resolved safely. Launch from the
repository root:

    python -m uvicorn zeroshield.api.app:app --reload

POST /experiments/{id}/runs is asynchronous (Milestone 21): it queues a job
on RabbitMQ and returns immediately. A separate zeroshield.worker process
consumes the queue, executes the run, and is the sole place SafetyPolicy is
evaluated for that job. Poll GET /jobs/{job_id} for status and result.

GET /metrics (Milestone 23) exposes operational Prometheus metrics (request
counts/latency, submitted-run counts) - see zeroshield.observability.metrics.
These are never a substitute for the scientific evidence under results/ or
GET /experiments/{id}/results.
"""

from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from zeroshield.api.errors import register_exception_handlers
from zeroshield.api.observability import PrometheusMiddleware, RequestContextMiddleware
from zeroshield.api.routes import (
    analyst,
    assets,
    audit,
    auth,
    controls,
    evidence,
    experiments,
    health,
    intelligence,
    jobs,
    metrics,
    revalidation,
    studio,
)
from zeroshield.observability.logging import configure_json_logging
from zeroshield.observability.tracing import configure_tracing

configure_json_logging()

app = FastAPI(
    title="ZeroShield API",
    description=(
        "REST interface over the ZeroShield Zero-Click Mitigation Validation Framework Core. "
        "This API never bypasses the existing SafetyPolicy. Experiment runs are asynchronous: "
        "POST /experiments/{id}/runs queues a job via RabbitMQ and returns immediately; poll "
        "GET /jobs/{job_id} for status and result. Every route except /health, /metrics, and "
        "/auth/login requires an authenticated session (V2 Phase 6) - see /auth/login."
    ),
    version="0.6.0",
)

# RequestContextMiddleware must run before PrometheusMiddleware sees the
# request so route handlers (and anything they call, e.g. audit logging)
# always have request.state.request_id available - see observability.py.
app.add_middleware(PrometheusMiddleware)
app.add_middleware(RequestContextMiddleware)
register_exception_handlers(app)

# V2 Phase 6, Step 5: distributed tracing. FastAPIInstrumentor wraps the ASGI
# app directly (not app.add_middleware), so its span is the outermost one,
# covering RequestContextMiddleware/PrometheusMiddleware/routing/handlers -
# the root of the browser->API leg of a run's trace (see
# zeroshield.observability.tracing for what happens next, across RabbitMQ).
configure_tracing("zeroshield-api")
FastAPIInstrumentor.instrument_app(app)
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(experiments.router)
app.include_router(evidence.router)
app.include_router(jobs.router)
app.include_router(metrics.router)
app.include_router(intelligence.router)
app.include_router(studio.router)
app.include_router(analyst.router)
app.include_router(assets.router)
app.include_router(controls.router)
app.include_router(revalidation.router)
app.include_router(audit.router)
