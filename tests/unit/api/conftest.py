from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from zeroshield.api import dependencies
from zeroshield.api.app import app

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
VPN_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-VPN-EXP-001.json"
TELECOM_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-TELECOM-EXP-001.json"


@pytest.fixture
def results_root(tmp_path: Path) -> Path:
    return tmp_path / "results"


@pytest.fixture
def client(results_root: Path) -> Iterator[TestClient]:
    """A TestClient with an isolated, temporary results directory.

    The real experiments/ directory is used as-is (so VPN/Telecom experiments are
    genuinely discoverable), but every run/results/evidence call writes to and reads
    from results_root (tmp_path-based), never the project's real results/ directory.
    raise_server_exceptions=False makes this client behave like a real HTTP client:
    it returns the response my exception handlers built instead of re-raising for
    debugger convenience (Starlette TestClient's default).
    """
    app.dependency_overrides[dependencies.get_results_root] = lambda: results_root
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
