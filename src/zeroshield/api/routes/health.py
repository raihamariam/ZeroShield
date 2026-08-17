"""Health/status routes.

GET /health is a cheap liveness probe (Docker healthcheck; the exact
{status, service} response shape is depended on elsewhere and is
deliberately left untouched).

GET /system/status (V2 Phase 4, Step 10) is the honest, best-effort
per-dependency check the frontend's System/Health view needs -
api/database/rabbitmq/worker/minio - each producing a real
DependencyHealthResponse, never a fabricated "green". Modeled on Phase 2's
ConnectorHealth shape (source/available/detail/checked_at).
"""

import os
from datetime import UTC, datetime

from fastapi import APIRouter

from zeroshield.api.schemas import DependencyHealthResponse, HealthResponse, SystemStatusResponse
from zeroshield.services.job_store import RUN_JOB_QUEUE_NAME

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns a simple machine-readable indicator that the API process is running.",
)
def get_health() -> HealthResponse:
    return HealthResponse(status="healthy", service="zeroshield")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _check_api() -> DependencyHealthResponse:
    # Reaching this line at all proves the API process is up.
    return DependencyHealthResponse(name="api", available=True, detail=None, checked_at=_now())


def _check_database() -> DependencyHealthResponse:
    checked_at = _now()
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        return DependencyHealthResponse(
            name="database",
            available=False,
            detail="DATABASE_URL is not configured",
            checked_at=checked_at,
        )
    try:
        from sqlalchemy import text

        from zeroshield.db.session import build_sessionmaker

        sessionmaker = build_sessionmaker()
        with sessionmaker() as session:
            session.execute(text("SELECT 1"))
        return DependencyHealthResponse(name="database", available=True, detail=None, checked_at=checked_at)
    except Exception as exc:  # noqa: BLE001 - a health check must report failure, never raise
        return DependencyHealthResponse(
            name="database", available=False, detail=str(exc), checked_at=checked_at
        )


def _check_rabbitmq_and_worker() -> tuple[DependencyHealthResponse, DependencyHealthResponse]:
    """Worker liveness has no dedicated heartbeat mechanism, so it is inferred
    honestly from the real consumer count on the run-job queue rather than
    invented: zero consumers truthfully means no worker process is currently
    attached, and an unreachable broker means worker status cannot be
    determined at all."""
    checked_at = _now()
    rabbitmq_url = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    try:
        import pika

        params = pika.URLParameters(rabbitmq_url)
        params.socket_timeout = 2.0
        connection = pika.BlockingConnection(params)
        try:
            channel = connection.channel()
            result = channel.queue_declare(queue=RUN_JOB_QUEUE_NAME, durable=True, passive=True)
            consumer_count = result.method.consumer_count
        finally:
            connection.close()
    except Exception as exc:  # noqa: BLE001
        rabbitmq = DependencyHealthResponse(
            name="rabbitmq", available=False, detail=str(exc), checked_at=checked_at
        )
        worker = DependencyHealthResponse(
            name="worker",
            available=False,
            detail="cannot be checked: rabbitmq is unreachable",
            checked_at=checked_at,
        )
        return rabbitmq, worker

    rabbitmq = DependencyHealthResponse(name="rabbitmq", available=True, detail=None, checked_at=checked_at)
    worker = DependencyHealthResponse(
        name="worker",
        available=consumer_count > 0,
        detail=f"{consumer_count} consumer(s) attached to queue '{RUN_JOB_QUEUE_NAME}'",
        checked_at=checked_at,
    )
    return rabbitmq, worker


def _check_minio() -> DependencyHealthResponse:
    checked_at = _now()
    if os.environ.get("ZEROSHIELD_EVIDENCE_BACKEND", "local").strip().lower() != "minio":
        return DependencyHealthResponse(
            name="minio",
            available=False,
            detail="ZEROSHIELD_EVIDENCE_BACKEND is not 'minio' (evidence is stored on the local "
            "filesystem)",
            checked_at=checked_at,
        )
    try:
        from zeroshield.repositories.minio_evidence_repository import default_minio_client

        default_minio_client().list_buckets()
        return DependencyHealthResponse(name="minio", available=True, detail=None, checked_at=checked_at)
    except Exception as exc:  # noqa: BLE001
        return DependencyHealthResponse(name="minio", available=False, detail=str(exc), checked_at=checked_at)


@router.get(
    "/system/status",
    response_model=SystemStatusResponse,
    summary="Infrastructure dependency health (API/database/RabbitMQ/worker/MinIO)",
    description="Best-effort, short-timeout checks against each real dependency (V2 Phase 4, Step "
    "10) - never a fabricated green light. Worker liveness is inferred from the real RabbitMQ "
    "consumer count on the run-job queue, since no separate worker heartbeat mechanism exists.",
)
def get_system_status() -> SystemStatusResponse:
    rabbitmq, worker = _check_rabbitmq_and_worker()
    return SystemStatusResponse(
        dependencies=[_check_api(), _check_database(), rabbitmq, worker, _check_minio()]
    )
