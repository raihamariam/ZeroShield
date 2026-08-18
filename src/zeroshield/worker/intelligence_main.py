"""RabbitMQ consume loop for intelligence-sync jobs - separate queue and
separate process from the experiment-run worker (zeroshield.worker.main), so
a slow/large NVD sync never competes with or blocks experiment-run job
processing (Step 7). Runs from the same image as api/worker/dashboard, just a
different `command:` in docker-compose.yml, consistent with the existing
one-image-many-commands pattern - not a new microservice.

Also starts a small Prometheus metrics HTTP server (V2 Phase 6, Step 5),
matching zeroshield.worker.main's WORKER_METRICS_PORT pattern, so
zeroshield_intelligence_syncs_total is scrapable from this process too - on
its own port so it never collides with the run-job worker when both run on
the same host.

Launch with:  python -m zeroshield.worker.intelligence_main
"""

import logging
import os
from pathlib import Path
from typing import Any

from opentelemetry import trace
from prometheus_client import start_http_server
from pydantic import ValidationError

from zeroshield.db.session import build_sessionmaker
from zeroshield.intelligence.connectors.registry import build_connector
from zeroshield.intelligence.messaging import (
    INTELLIGENCE_SYNC_QUEUE_NAME,
    IntelligenceSyncJobMessage,
)
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.intelligence.sync_service import run_sync
from zeroshield.observability.logging import configure_json_logging
from zeroshield.observability.tracing import configure_tracing, extract_trace_context, get_tracer
from zeroshield.worker.broker import connect_with_retry

_tracer = get_tracer("zeroshield.worker.intelligence")

logger = logging.getLogger("zeroshield.worker.intelligence")


def get_rabbitmq_url() -> str:
    return os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")


def get_metrics_port() -> int:
    return int(os.environ.get("INTELLIGENCE_WORKER_METRICS_PORT", "9201"))


def get_experiments_dir() -> Path:
    return Path.cwd() / "experiments"


def handle_message_body(
    body: bytes,
    *,
    repository: VulnerabilityRepository,
    experiments_dir: Path,
    headers: dict[str, str] | None = None,
) -> None:
    """Never raises - a malformed message is logged and dropped, matching
    zeroshield.worker.main.handle_message_body's failure-isolation
    guarantee (Milestone 26 hardening). run_sync() already converts every
    known failure mode (fetch failure, per-record normalisation/validation
    failure) into a persisted IntelligenceSync status; this is a last-resort
    guard for something even it did not anticipate.

    `headers` carries the AMQP message headers (V2 Phase 6, Step 5) - see
    zeroshield.worker.main.handle_message_body's identical trace-propagation
    docstring."""
    try:
        message = IntelligenceSyncJobMessage.model_validate_json(body)
    except ValidationError as exc:
        logger.error("dropping malformed intelligence sync message: %s", exc)
        return

    logger.info("processing intelligence sync %s (%s)", message.sync_id, message.source.value)
    parent_context = extract_trace_context(headers or {})
    with _tracer.start_as_current_span(
        "intelligence_worker.run_sync", context=parent_context, kind=trace.SpanKind.CONSUMER
    ) as span:
        span.set_attribute("zeroshield.sync_id", message.sync_id)
        span.set_attribute("zeroshield.source", message.source.value)
        try:
            connector = build_connector(message.source)
            run_sync(
                connector,
                sync_id=message.sync_id,
                repository=repository,
                since=message.since,
                experiments_dir=experiments_dir,
            )
        except Exception as exc:
            span.record_exception(exc)
            logger.exception("unexpected error processing intelligence sync %s", message.sync_id)


def main() -> None:  # pragma: no cover - requires a live RabbitMQ+Postgres; see tests/unit/worker
    configure_json_logging()
    configure_tracing("zeroshield-intelligence-worker")

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit(
            "DATABASE_URL is required to run the intelligence worker - the threat-intelligence "
            "system of record is PostgreSQL-backed (Step 1), unlike the optional RunRepository."
        )
    repository = VulnerabilityRepository(build_sessionmaker())
    experiments_dir = get_experiments_dir()

    metrics_port = get_metrics_port()
    start_http_server(metrics_port)
    logger.info("intelligence worker Prometheus metrics available on :%d/metrics", metrics_port)

    connection = connect_with_retry(get_rabbitmq_url())
    channel = connection.channel()
    channel.queue_declare(queue=INTELLIGENCE_SYNC_QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)

    def _on_message(ch: Any, method: Any, properties: Any, body: bytes) -> None:
        handle_message_body(
            body, repository=repository, experiments_dir=experiments_dir, headers=properties.headers
        )
        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=INTELLIGENCE_SYNC_QUEUE_NAME, on_message_callback=_on_message)
    logger.info(
        "zeroshield intelligence worker started, waiting for jobs on queue '%s'",
        INTELLIGENCE_SYNC_QUEUE_NAME,
    )
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    finally:
        connection.close()


if __name__ == "__main__":  # pragma: no cover
    main()
