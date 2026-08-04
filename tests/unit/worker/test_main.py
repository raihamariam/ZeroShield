import os
from pathlib import Path

import pytest

from zeroshield.worker import main as worker_main


def test_get_rabbitmq_url_default() -> None:
    os.environ.pop("RABBITMQ_URL", None)
    assert worker_main.get_rabbitmq_url() == "amqp://guest:guest@localhost:5672/"


def test_get_rabbitmq_url_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RABBITMQ_URL", "amqp://user:pass@broker:5672/")
    assert worker_main.get_rabbitmq_url() == "amqp://user:pass@broker:5672/"


def test_get_experiments_dir_defaults_to_cwd_experiments() -> None:
    assert worker_main.get_experiments_dir() == Path.cwd() / "experiments"


def test_get_results_root_defaults_to_cwd_results() -> None:
    assert worker_main.get_results_root() == Path.cwd() / "results"


def test_get_jobs_dir_defaults_to_cwd_jobs() -> None:
    assert worker_main.get_jobs_dir() == Path.cwd() / "jobs"


def test_get_metrics_port_default() -> None:
    os.environ.pop("WORKER_METRICS_PORT", None)
    assert worker_main.get_metrics_port() == 9200


def test_get_metrics_port_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORKER_METRICS_PORT", "9999")
    assert worker_main.get_metrics_port() == 9999
