"""Publishes queued run jobs to RabbitMQ. A short-lived connection per publish
call - simple and robust for a low-traffic research API, consistent with how
the rest of the project opens/closes file handles per operation rather than
holding persistent state across requests.
"""

import pika

from zeroshield.services.job_store import RUN_JOB_QUEUE_NAME, RunJobMessage


def publish_run_job(message: RunJobMessage, *, rabbitmq_url: str) -> None:
    connection = pika.BlockingConnection(pika.URLParameters(rabbitmq_url))
    try:
        channel = connection.channel()
        channel.queue_declare(queue=RUN_JOB_QUEUE_NAME, durable=True)
        channel.basic_publish(
            exchange="",
            routing_key=RUN_JOB_QUEUE_NAME,
            body=message.model_dump_json().encode("utf-8"),
            properties=pika.BasicProperties(delivery_mode=2, content_type="application/json"),
        )
    finally:
        connection.close()
