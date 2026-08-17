"""Async intelligence-sync job queue - mirrors zeroshield.services.job_store's
RunJobMessage/RUN_JOB_QUEUE_NAME pattern (Milestone 21), on its own queue so a
slow/large sync never competes with or blocks experiment-run jobs (Step 7:
"Use RabbitMQ/background workers for large syncs. Do not block API requests.")
"""

from datetime import datetime

import pika
from pydantic import BaseModel, ConfigDict

from zeroshield.models.vulnerability import VulnerabilitySourceName
from zeroshield.observability.tracing import inject_trace_context

INTELLIGENCE_SYNC_QUEUE_NAME = "zeroshield.intelligence_syncs"


class IntelligenceSyncJobMessage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sync_id: str
    source: VulnerabilitySourceName
    since: datetime | None = None


def publish_sync_job(message: IntelligenceSyncJobMessage, *, rabbitmq_url: str) -> None:
    connection = pika.BlockingConnection(pika.URLParameters(rabbitmq_url))
    try:
        channel = connection.channel()
        channel.queue_declare(queue=INTELLIGENCE_SYNC_QUEUE_NAME, durable=True)
        headers = inject_trace_context({})
        channel.basic_publish(
            exchange="",
            routing_key=INTELLIGENCE_SYNC_QUEUE_NAME,
            body=message.model_dump_json().encode("utf-8"),
            properties=pika.BasicProperties(
                delivery_mode=2, content_type="application/json", headers=headers
            ),
        )
    finally:
        connection.close()
