"""End-to-end async workflow against a REAL RabbitMQ broker - not the fake
publisher used everywhere else in the test suite (tests/unit/api/conftest.py
overrides get_publisher precisely so `pytest` never needs live infrastructure).
This is the one place that intentionally uses the real zeroshield.api.messaging.
publish_run_job and a real pika connection, proving the actual message
serialisation/queue-delivery mechanics work - something a mocked
`basic_publish` call can structurally never verify.

SAFETY: this test does NOT fall back to get_rabbitmq_url()'s production default
(amqp://guest:guest@localhost:5672/). An earlier version of this test did, and
on this development machine that silently connected to a completely unrelated
RabbitMQ container from a different project that happened to already be using
the standard port 5672 on the host - it created (and was cleaned up afterwards
by hand) a queue in infrastructure this test has no business touching. This
test now only runs when explicitly opted into via ZEROSHIELD_E2E_RABBITMQ_URL,
a distinctly-named environment variable with no default, so it can never
silently probe or mutate a broker the developer didn't deliberately point it at.

Run with:
    docker compose up -d rabbitmq
    # rabbitmq's AMQP port is host-exposed on 5673 (see docker-compose.yml)
    ZEROSHIELD_E2E_RABBITMQ_URL=amqp://guest:guest@localhost:5673/ \
        pytest tests/integration/test_api_worker_real_broker.py

Happy path only: denial/failure-path scenarios are Milestone 26's scope.
"""

import os
import socket
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import pika
import pytest

from zeroshield.api.messaging import publish_run_job
from zeroshield.policies import ExecutionContext
from zeroshield.services.job_store import RUN_JOB_QUEUE_NAME, JobStatus, JobStore, RunJobMessage
from zeroshield.worker.processor import process_run_job

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"

_RABBITMQ_URL = os.environ.get("ZEROSHIELD_E2E_RABBITMQ_URL")


def _broker_reachable(url: str) -> bool:
    parsed = urlparse(url)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5672), timeout=1.5):
            return True
    except OSError:
        return False


_skip_reason = (
    "Set ZEROSHIELD_E2E_RABBITMQ_URL to run this test against a real broker you control "
    "(e.g. amqp://guest:guest@localhost:5673/ after `docker compose up -d rabbitmq`). "
    "Deliberately does not fall back to any default host/port, to avoid silently "
    "connecting to an unrelated broker that happens to be reachable on this machine."
)
if _RABBITMQ_URL is not None and not _broker_reachable(_RABBITMQ_URL):
    _skip_reason = f"ZEROSHIELD_E2E_RABBITMQ_URL is set but not reachable: {_RABBITMQ_URL}"
    _RABBITMQ_URL = None

pytestmark = pytest.mark.skipif(_RABBITMQ_URL is None, reason=_skip_reason)


def test_real_publish_then_consume_then_process_vpn_job(tmp_path: Path) -> None:
    assert _RABBITMQ_URL is not None  # narrows the type for mypy; guaranteed by skipif above
    job_id = f"JOB-e2e-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"

    connection = pika.BlockingConnection(pika.URLParameters(_RABBITMQ_URL))
    try:
        channel = connection.channel()
        declared = channel.queue_declare(queue=RUN_JOB_QUEUE_NAME, durable=True)
        if declared.method.message_count > 0:
            pytest.skip(
                f"queue '{RUN_JOB_QUEUE_NAME}' already has "
                f"{declared.method.message_count} message(s) - run this test against an "
                "isolated broker with no other producer/consumer active"
            )

        # the real publisher used by POST /experiments/{id}/runs - not mocked
        publish_run_job(
            RunJobMessage(
                job_id=job_id,
                experiment_id="ZC-VPN-EXP-001",
                execution_context=ExecutionContext.LOCAL_UNIT_TEST,
            ),
            rabbitmq_url=_RABBITMQ_URL,
        )

        method, _properties, body = channel.basic_get(queue=RUN_JOB_QUEUE_NAME, auto_ack=False)
        assert method is not None, "published message was not delivered back by the real broker"
        channel.basic_ack(delivery_tag=method.delivery_tag)
    finally:
        connection.close()

    # real deserialisation of what actually came off the wire, matching main.py's consume loop
    message = RunJobMessage.model_validate_json(body)
    assert message.job_id == job_id
    assert message.experiment_id == "ZC-VPN-EXP-001"
    assert message.execution_context == ExecutionContext.LOCAL_UNIT_TEST

    job_store = JobStore(tmp_path / "jobs")
    results_root = tmp_path / "results"
    process_run_job(
        message.job_id,
        message.experiment_id,
        message.execution_context,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=job_store,
    )

    record = job_store.load(job_id)
    assert record is not None
    assert record.status == JobStatus.COMPLETED
    assert record.result is not None
    assert record.result.total_cases == 22
    assert (results_root / "ZC-VPN-EXP-001" / "comparison.json").is_file()
