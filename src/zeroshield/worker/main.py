"""RabbitMQ consume loop. Thin: parses each message and hands off to
processor.process_run_job(); no execution logic lives here.

Also starts a small Prometheus metrics HTTP server (Milestone 23) so an
external Prometheus instance can scrape this process directly - the worker
is a long-running process with no other HTTP surface, unlike the API, which
serves GET /metrics itself.

Launch with:  python -m zeroshield.worker   (or the zeroshield-worker console script)
"""

import logging
import os
from pathlib import Path
from typing import Any

import pika
from prometheus_client import start_http_server
from pydantic import ValidationError

from zeroshield.repositories import NullRunRepository, RunRepository
from zeroshield.services.job_store import RUN_JOB_QUEUE_NAME, JobStore, RunJobMessage
from zeroshield.worker.processor import process_run_job

logger = logging.getLogger("zeroshield.worker")


def get_rabbitmq_url() -> str:
    return os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")


def get_run_repository() -> RunRepository:
    """Builds a PostgresRunRepository if DATABASE_URL is configured, else the
    no-op NullRunRepository - so the worker runs with zero Postgres
    dependency unless a database is actually configured, per V1
    compatibility. The sqlalchemy/psycopg import is local/guarded so the
    "db" extra stays optional when DATABASE_URL is unset, consistent with
    how RABBITMQ_URL/MINIO_* are handled elsewhere in this module/project.
    """
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        return NullRunRepository()

    from zeroshield.db.session import build_sessionmaker
    from zeroshield.repositories.postgres_run_repository import PostgresRunRepository

    return PostgresRunRepository(build_sessionmaker())


def get_assurance_repository() -> Any | None:
    """Builds an AssuranceRepository (V2 Phase 5) if DATABASE_URL is
    configured, else None - control-validation history is auxiliary
    observability layered on top of the run, same as run_repository above,
    so its absence must never affect job processing (see
    zeroshield.worker.processor._record_control_validation)."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        return None

    from zeroshield.assurance.repository import AssuranceRepository
    from zeroshield.db.session import build_sessionmaker

    return AssuranceRepository(build_sessionmaker())


def get_experiments_dir() -> Path:
    return Path.cwd() / "experiments"


def get_results_root() -> Path:
    return Path.cwd() / "results"


def get_jobs_dir() -> Path:
    return Path.cwd() / "jobs"


def get_metrics_port() -> int:
    return int(os.environ.get("WORKER_METRICS_PORT", "9200"))


def handle_message_body(
    body: bytes,
    *,
    experiments_dir: Path,
    results_root: Path,
    job_store: JobStore,
    run_repository: RunRepository | None = None,
    assurance_repository: Any | None = None,
) -> None:
    """Parses and processes one queue message. Never raises: a malformed or
    otherwise unprocessable message is logged and dropped rather than
    crashing the consume loop, which would take the whole worker process
    down and - since an unacked message is redelivered - cause the exact
    same "poison" message to crash it again forever on reconnect (Milestone
    26 failure-path hardening; SRS S10.3 threat model: "Queue job tampering
    - ... idempotency").

    process_run_job() already handles every known failure mode internally
    (denial, unrunnable experiment, unexpected error) and records a
    terminal job status for each; the broad except below is a last-resort
    guard for something even it did not anticipate, e.g. the job store
    itself being unwritable. Directly testable without a broker.
    """
    try:
        message = RunJobMessage.model_validate_json(body)
    except ValidationError as exc:
        logger.error("dropping malformed queue message: %s", exc)
        return

    logger.info("processing job %s (%s)", message.job_id, message.experiment_id)
    try:
        process_run_job(
            message.job_id,
            message.experiment_id,
            message.execution_context,
            experiments_dir=experiments_dir,
            results_root=results_root,
            job_store=job_store,
            run_repository=run_repository,
            assurance_repository=assurance_repository,
        )
    except Exception:
        logger.exception("unexpected error processing job %s", message.job_id)


def main() -> None:  # pragma: no cover - requires a live RabbitMQ broker; see tests/unit/worker
    logging.basicConfig(level=logging.INFO)

    job_store = JobStore(get_jobs_dir())
    experiments_dir = get_experiments_dir()
    results_root = get_results_root()
    run_repository = get_run_repository()
    assurance_repository = get_assurance_repository()

    metrics_port = get_metrics_port()
    start_http_server(metrics_port)
    logger.info("worker Prometheus metrics available on :%d/metrics", metrics_port)

    connection = pika.BlockingConnection(pika.URLParameters(get_rabbitmq_url()))
    channel = connection.channel()
    channel.queue_declare(queue=RUN_JOB_QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)

    def _on_message(ch: Any, method: Any, properties: Any, body: bytes) -> None:
        # handle_message_body never raises, so the message is always acked
        # here - a permanently malformed message must never be redelivered
        # forever; a genuinely transient failure is still visible via the
        # FAILED job record process_run_job writes, or the log line above.
        handle_message_body(
            body,
            experiments_dir=experiments_dir,
            results_root=results_root,
            job_store=job_store,
            run_repository=run_repository,
            assurance_repository=assurance_repository,
        )
        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=RUN_JOB_QUEUE_NAME, on_message_callback=_on_message)
    logger.info("zeroshield worker started, waiting for jobs on queue '%s'", RUN_JOB_QUEUE_NAME)
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    finally:
        connection.close()
