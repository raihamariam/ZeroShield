"""Tests publish_run_job against a mocked pika.BlockingConnection - no live broker
needed. Genuine end-to-end delivery (a real worker consuming a real published
message) is verified manually against a real broker; see the Milestone 21 report.
"""

import json
from unittest.mock import MagicMock, patch

from zeroshield.api.messaging import publish_run_job
from zeroshield.policies import ExecutionContext
from zeroshield.services.job_store import RUN_JOB_QUEUE_NAME, RunJobMessage


def test_publish_run_job_declares_queue_and_publishes_message_body() -> None:
    message = RunJobMessage(
        job_id="JOB-abc", experiment_id="ZC-VPN-EXP-001", execution_context=ExecutionContext.LOCAL_UNIT_TEST
    )
    mock_channel = MagicMock()
    mock_connection = MagicMock()
    mock_connection.channel.return_value = mock_channel

    with patch("zeroshield.api.messaging.pika.BlockingConnection", return_value=mock_connection) as mock_conn_cls:
        publish_run_job(message, rabbitmq_url="amqp://guest:guest@localhost:5672/")

    mock_conn_cls.assert_called_once()
    mock_channel.queue_declare.assert_called_once_with(queue=RUN_JOB_QUEUE_NAME, durable=True)

    mock_channel.basic_publish.assert_called_once()
    _, kwargs = mock_channel.basic_publish.call_args
    assert kwargs["routing_key"] == RUN_JOB_QUEUE_NAME
    published_body = json.loads(kwargs["body"].decode("utf-8"))
    assert published_body["job_id"] == "JOB-abc"
    assert published_body["experiment_id"] == "ZC-VPN-EXP-001"
    assert published_body["execution_context"] == "local_unit_test"


def test_publish_run_job_closes_connection_even_if_publish_fails() -> None:
    message = RunJobMessage(
        job_id="JOB-fail", experiment_id="ZC-VPN-EXP-001", execution_context=ExecutionContext.LOCAL_UNIT_TEST
    )
    mock_channel = MagicMock()
    mock_channel.basic_publish.side_effect = RuntimeError("broker unavailable")
    mock_connection = MagicMock()
    mock_connection.channel.return_value = mock_channel

    with patch("zeroshield.api.messaging.pika.BlockingConnection", return_value=mock_connection):
        try:
            publish_run_job(message, rabbitmq_url="amqp://guest:guest@localhost:5672/")
        except RuntimeError:
            pass

    mock_connection.close.assert_called_once()
