"""Central exception -> structured HTTP response mapping.

Route handlers never format error JSON themselves. As of Milestone 21,
PolicyRefusalError and ExperimentServiceError are raised only inside
zeroshield.worker (via zeroshield.worker.processor.process_run_job, which
runs in a separate process and has its own equivalent handling that never
leaks either a raw exception message or a stack trace into a job's stored
error) - no current API route can trigger either, since POST
/experiments/{id}/runs only queues a job and never calls
experiment_service.run_experiment() itself. Only the generic catch-all
below remains reachable from this process, e.g. for corrupted/incomplete
evidence encountered while reading GET /results or /evidence.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("zeroshield.api")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error in %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "detail": "an internal error occurred"},
        )
