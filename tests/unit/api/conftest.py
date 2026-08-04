from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.services.job_store import RunJobMessage

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
VPN_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-VPN-EXP-001.json"
TELECOM_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-TELECOM-EXP-001.json"


@pytest.fixture
def results_root(tmp_path: Path) -> Path:
    return tmp_path / "results"


@pytest.fixture
def jobs_dir(tmp_path: Path) -> Path:
    return tmp_path / "jobs"


@pytest.fixture
def published_messages() -> list[RunJobMessage]:
    """Records what submit_run() would have published to RabbitMQ."""
    return []


@pytest.fixture
def client(
    results_root: Path, jobs_dir: Path, published_messages: list[RunJobMessage]
) -> Iterator[TestClient]:
    """A TestClient with isolated, temporary results/jobs directories and a fake publisher.

    The real experiments/ directory is used as-is (so VPN/Telecom experiments are
    genuinely discoverable), but every run/results/evidence/job call writes to and
    reads from results_root/jobs_dir (tmp_path-based), never the project's real
    directories. get_publisher is overridden with a fake that just records the
    message into published_messages instead of requiring a live RabbitMQ broker -
    genuine end-to-end message-queue delivery is verified manually against a real
    broker (see the Milestone 21 report), not as part of this automated suite, so
    that `pytest` never depends on external infrastructure being up.
    raise_server_exceptions=False makes this client behave like a real HTTP client:
    it returns the response my exception handlers built instead of re-raising for
    debugger convenience (Starlette TestClient's default).
    """
    app.dependency_overrides[dependencies.get_results_root] = lambda: results_root
    app.dependency_overrides[dependencies.get_jobs_dir] = lambda: jobs_dir
    app.dependency_overrides[dependencies.get_publisher] = lambda: published_messages.append
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
