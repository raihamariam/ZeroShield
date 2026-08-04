import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from zeroshield.api import dependencies
from zeroshield.policies import ExecutionContext
from zeroshield.services.job_store import JobStore, RunJobMessage


def test_get_experiments_dir_defaults_to_cwd_experiments() -> None:
    assert dependencies.get_experiments_dir() == Path.cwd() / "experiments"


def test_get_results_root_defaults_to_cwd_results() -> None:
    assert dependencies.get_results_root() == Path.cwd() / "results"


def test_get_jobs_dir_defaults_to_cwd_jobs() -> None:
    assert dependencies.get_jobs_dir() == Path.cwd() / "jobs"


def test_get_job_store_wraps_the_given_directory(tmp_path: Path) -> None:
    store = dependencies.get_job_store(tmp_path / "jobs")
    assert isinstance(store, JobStore)


def test_get_rabbitmq_url_default() -> None:
    os.environ.pop("RABBITMQ_URL", None)
    assert dependencies.get_rabbitmq_url() == "amqp://guest:guest@localhost:5672/"


def test_get_rabbitmq_url_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RABBITMQ_URL", "amqp://user:pass@broker:5672/")
    assert dependencies.get_rabbitmq_url() == "amqp://user:pass@broker:5672/"


def test_get_publisher_returns_a_callable() -> None:
    publish = dependencies.get_publisher("amqp://guest:guest@localhost:5672/")
    assert callable(publish)


def test_get_publisher_closure_delegates_to_publish_run_job() -> None:
    """Confirms the returned closure forwards to publish_run_job with the captured
    rabbitmq_url, against a mocked pika connection - no live broker needed."""
    mock_channel = MagicMock()
    mock_connection = MagicMock()
    mock_connection.channel.return_value = mock_channel

    publish = dependencies.get_publisher("amqp://guest:guest@localhost:5672/")
    message = RunJobMessage(
        job_id="JOB-abc", experiment_id="ZC-VPN-EXP-001", execution_context=ExecutionContext.LOCAL_UNIT_TEST
    )
    with patch("zeroshield.api.messaging.pika.BlockingConnection", return_value=mock_connection):
        publish(message)

    mock_channel.basic_publish.assert_called_once()
