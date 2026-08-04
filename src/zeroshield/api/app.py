"""ZeroShield REST API (Milestone 19).

A thin FastAPI interface layer over the existing ZeroShield Core, via
zeroshield.services.experiment_service. No safety, strategy, orchestration,
or metric logic is implemented in this package - see errors.py for the
central exception -> HTTP response mapping and dependencies.py for how
experiment_id path parameters are resolved safely. Launch from the
repository root:

    python -m uvicorn zeroshield.api.app:app --reload
"""

from fastapi import FastAPI

from zeroshield.api.errors import register_exception_handlers
from zeroshield.api.routes import evidence, experiments, health

app = FastAPI(
    title="ZeroShield API",
    description=(
        "REST interface over the ZeroShield Zero-Click Mitigation Validation Framework Core. "
        "Phase 1 synthetic experiments only - see /experiments for what is currently registered. "
        "This API never bypasses the existing SafetyPolicy."
    ),
    version="0.1.0",
)

register_exception_handlers(app)
app.include_router(health.router)
app.include_router(experiments.router)
app.include_router(evidence.router)
