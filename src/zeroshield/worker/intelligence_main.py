"""RabbitMQ consume loop for intelligence-sync jobs - separate queue and
separate process from the experiment-run worker (zeroshield.worker.main), so
a slow/large NVD sync never competes with or blocks experiment-run job
processing (Step 7). Runs from the same image as api/worker/dashboard, just a
different `command:` in docker-compose.yml, consistent with the existing
one-image-many-commands pattern - not a new microservice.

Launch with:  python -m zeroshield.worker.intelligence_main
"""

import logging
import os
from pathlib import Path
from typing import Any

import pika
from pydantic import ValidationError

from zeroshield.db.session import build_sessionmaker
from zeroshield.intelligence.connectors.registry import build_connector
from zeroshield.intelligence.messaging import (
    INTELLIGENCE_SYNC_QUEUE_NAME,
    IntelligenceSyncJobMessage,
)
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.intelligence.sync_service import run_sync

logger = logging.getLogger("zeroshield.worker.intelligence")


def get_rabbitmq_url() -> str:
    return os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")


def get_experiments_dir() -> Path:
    return Path.cwd() / "experiments"


def handle_message_body(
    body: bytes, *, repository: VulnerabilityRepository, experiments_dir: Path
) -> None:
    """Never raises - a malformed message is logged and dropped, matching
    zeroshield.worker.main.handle_message_body's failure-isolation
    guarantee (Milestone 26 hardening). run_sync() already converts every
    known failure mode (fetch failure, per-record normalisation/validation
    failure) into a persisted IntelligenceSync status; this is a last-resort
    guard for something even it did not anticipate."""
    try:
        message = IntelligenceSyncJobMessage.model_validate_json(body)
    except ValidationError as exc:
        logger.error("dropping malformed intelligence sync message: %s", exc)
        return

    logger.info("processing intelligence sync %s (%s)", message.sync_id, message.source.value)
    try:
        connector = build_connector(message.source)
        run_sync(
            connector,
            sync_id=message.sync_id,
            repository=repository,
            since=message.since,
            experiments_dir=experiments_dir,
        )
    except Exception:
        logger.exception("unexpected error processing intelligence sync %s", message.sync_id)


def main() -> None:  # pragma: no cover - requires a live RabbitMQ+Postgres; see tests/unit/worker
    logging.basicConfig(level=logging.INFO)

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit(
            "DATABASE_URL is required to run the intelligence worker - the threat-intelligence "
            "system of record is PostgreSQL-backed (Step 1), unlike the optional RunRepository."
        )
    repository = VulnerabilityRepository(build_sessionmaker())
    experiments_dir = get_experiments_dir()

    connection = pika.BlockingConnection(pika.URLParameters(get_rabbitmq_url()))
    channel = connection.channel()
    channel.queue_declare(queue=INTELLIGENCE_SYNC_QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)

    def _on_message(ch: Any, method: Any, properties: Any, body: bytes) -> None:
        handle_message_body(body, repository=repository, experiments_dir=experiments_dir)
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
