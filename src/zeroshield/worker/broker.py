"""Resilient RabbitMQ connection helper, shared by worker.main and
worker.intelligence_main (final release verification fix).

A fresh `docker compose up` starts every service at once; RabbitMQ's own
healthcheck (`rabbitmq-diagnostics ping`) can report healthy slightly
before the AMQP listener on :5672 is actually accepting connections - a
real, reproduced race (not hypothetical) on a genuinely parallel first
start. Previously both workers made exactly one `pika.BlockingConnection()`
attempt at startup and crashed immediately (exit 1) on
`AMQPConnectionError`, which `docker-compose.yml`'s `depends_on:
condition: service_healthy` on rabbitmq did not protect against, since
"healthy" and "actually accepting AMQP connections" turned out not to be
the same moment. Retrying with a short bounded backoff is standard practice
for this exact class of container-orchestration race and costs nothing on
the far more common case where the broker is already ready.
"""

import logging
import time

import pika

logger = logging.getLogger("zeroshield.worker.broker")

CONNECT_MAX_ATTEMPTS = 30
CONNECT_RETRY_DELAY_SECONDS = 2.0


def connect_with_retry(
    rabbitmq_url: str,
    *,
    max_attempts: int = CONNECT_MAX_ATTEMPTS,
    delay_seconds: float = CONNECT_RETRY_DELAY_SECONDS,
) -> pika.BlockingConnection:
    """Connects to RabbitMQ, retrying on AMQPConnectionError up to
    max_attempts times (default: 30 x 2s = up to 60s) before giving up and
    letting the final exception propagate - a genuinely absent/misconfigured
    broker still fails loudly, just not on the first transient race."""
    last_error: pika.exceptions.AMQPConnectionError | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return pika.BlockingConnection(pika.URLParameters(rabbitmq_url))
        except pika.exceptions.AMQPConnectionError as exc:
            last_error = exc
            if attempt < max_attempts:
                logger.warning(
                    "RabbitMQ connection attempt %d/%d failed (%s) - retrying in %.0fs",
                    attempt, max_attempts, exc, delay_seconds,
                )
                time.sleep(delay_seconds)
    assert last_error is not None  # loop always sets it before exhausting attempts
    raise last_error
