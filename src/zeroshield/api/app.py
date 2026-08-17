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

from zeroshield.api.errors import register_exception_handlers
from zeroshield.api.observability import PrometheusMiddleware
from zeroshield.api.routes import (
    analyst,
    assets,
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

app = FastAPI(
    title="ZeroShield API",
    description=(
        "REST interface over the ZeroShield Zero-Click Mitigation Validation Framework Core. "
        "Phase 1 synthetic experiments only - see /experiments for what is currently registered. "
        "This API never bypasses the existing SafetyPolicy. Experiment runs are asynchronous: "
        "POST /experiments/{id}/runs queues a job via RabbitMQ and returns immediately; poll "
        "GET /jobs/{job_id} for status and result."
    ),
    version="0.3.0",
)

app.add_middleware(PrometheusMiddleware)
register_exception_handlers(app)
app.include_router(health.router)
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
