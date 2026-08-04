from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.services.job_store import RunJobMessage


@pytest.fixture
def results_root(tmp_path: Path) -> Path:
    return tmp_path / "results"


@pytest.fixture
def jobs_dir(tmp_path: Path) -> Path:
    return tmp_path / "jobs"


@pytest.fixture
def published_messages() -> list[RunJobMessage]:
    return []


@pytest.fixture
def client(
    results_root: Path, jobs_dir: Path, published_messages: list[RunJobMessage]
) -> Iterator[TestClient]:
    """Same wiring as tests/unit/api/conftest.py's client fixture: the real
    experiments/ directory, isolated tmp_path results/jobs directories, and a
    fake publisher so no live RabbitMQ broker is required."""
    app.dependency_overrides[dependencies.get_results_root] = lambda: results_root
    app.dependency_overrides[dependencies.get_jobs_dir] = lambda: jobs_dir
    app.dependency_overrides[dependencies.get_publisher] = lambda: published_messages.append
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
