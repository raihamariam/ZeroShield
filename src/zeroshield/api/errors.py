"""Central exception -> structured HTTP response mapping.

Route handlers never format error JSON themselves and never catch these
exceptions - this keeps error shape consistent and guarantees the safety
gate (PolicyRefusalError) is reported the same way everywhere it can occur.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from zeroshield.runners import PolicyRefusalError
from zeroshield.services.experiment_service import ExperimentServiceError

logger = logging.getLogger("zeroshield.api")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(PolicyRefusalError)
    async def handle_policy_refusal(request: Request, exc: PolicyRefusalError) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "error": "safety_policy_denied",
                "detail": "; ".join(exc.decision.reasons) or "denied by safety policy",
            },
        )

    @app.exception_handler(ExperimentServiceError)
    async def handle_service_error(request: Request, exc: ExperimentServiceError) -> JSONResponse:
        # exc's message may include server-side absolute filesystem paths (it is shared with
        # the CLI/dashboard, where that is useful); never forward it verbatim to API clients.
        logger.warning("experiment not runnable: %s", exc)
        return JSONResponse(
            status_code=422,
            content={
                "error": "experiment_not_runnable",
                "detail": "the experiment's configured dataset or processing strategy could not "
                "be resolved on this server.",
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error in %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "detail": "an internal error occurred"},
        )
