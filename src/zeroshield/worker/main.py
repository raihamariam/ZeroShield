"""RabbitMQ consume loop. Thin: parses each message and hands off to
processor.process_run_job(); no execution logic lives here.

Launch with:  python -m zeroshield.worker   (or the zeroshield-worker console script)
"""

import logging
import os
from pathlib import Path
from typing import Any

import pika

from zeroshield.services.job_store import RUN_JOB_QUEUE_NAME, JobStore, RunJobMessage
from zeroshield.worker.processor import process_run_job

logger = logging.getLogger("zeroshield.worker")


def get_rabbitmq_url() -> str:
    return os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")


def get_experiments_dir() -> Path:
    return Path.cwd() / "experiments"


def get_results_root() -> Path:
    return Path.cwd() / "results"


def get_jobs_dir() -> Path:
    return Path.cwd() / "jobs"


def main() -> None:  # pragma: no cover - requires a live RabbitMQ broker; see tests/unit/worker
    logging.basicConfig(level=logging.INFO)

    job_store = JobStore(get_jobs_dir())
    experiments_dir = get_experiments_dir()
    results_root = get_results_root()

    connection = pika.BlockingConnection(pika.URLParameters(get_rabbitmq_url()))
    channel = connection.channel()
    channel.queue_declare(queue=RUN_JOB_QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)

    def _on_message(ch: Any, method: Any, properties: Any, body: bytes) -> None:
        message = RunJobMessage.model_validate_json(body)
        logger.info("processing job %s (%s)", message.job_id, message.experiment_id)
        process_run_job(
            message.job_id,
            message.experiment_id,
            message.execution_context,
            experiments_dir=experiments_dir,
            results_root=results_root,
            job_store=job_store,
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
