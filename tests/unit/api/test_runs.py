import json
from pathlib import Path

from fastapi.testclient import TestClient

from zeroshield.api import dependencies
from zeroshield.api.app import app

REPO_ROOT = Path(__file__).resolve().parents[3]
VPN_EXPERIMENT_PATH = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"


def test_run_vpn_experiment_end_to_end(client: TestClient, results_root: Path) -> None:
    """Integration-level: real orchestration/runner/strategies via the API, no mocking."""
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["status"] == "completed"
    assert body["safety_passed"] is True
    assert body["total_cases"] == 22
    assert body["key_metrics"]["mitigation_block_rate"] == 1.0
    assert (results_root / "ZC-VPN-EXP-001" / "comparison.json").is_file()


def test_run_telecom_experiment_end_to_end(client: TestClient, results_root: Path) -> None:
    response = client.post(
        "/experiments/ZC-TELECOM-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-TELECOM-EXP-001"
    assert body["total_cases"] == 25


def test_run_denied_by_safety_policy_for_draft_experiment(
    client: TestClient, results_root: Path
) -> None:
    """Default execution_context is the strict one; ZC-VPN-EXP-001 is still draft."""
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "experiment_run"}
    )
    assert response.status_code == 403
    body = response.json()
    assert body["error"] == "safety_policy_denied"
    assert "SAFE-004" in body["detail"]
    # strongest proof: no evidence was ever written, the runner never executed a case
    assert not results_root.exists()


def test_run_denied_for_unsafe_configured_experiment(
    client: TestClient, results_root: Path, tmp_path: Path
) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["external_targeting"] = True
    data["approval_status"] = "approved"
    experiments_dir = tmp_path / "unsafe_experiments"
    experiments_dir.mkdir()
    (experiments_dir / "unsafe.json").write_text(json.dumps(data), encoding="utf-8")

    app.dependency_overrides[dependencies.get_experiments_dir] = lambda: experiments_dir
    try:
        response = client.post(
            "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "experiment_run"}
        )
    finally:
        del app.dependency_overrides[dependencies.get_experiments_dir]

    assert response.status_code == 403
    assert "SAFE-001" in response.json()["detail"]
    assert not results_root.exists()


def test_run_unknown_strategy_returns_422(client: TestClient, tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["baseline_strategy"] = "totally_unknown_strategy"
    experiments_dir = tmp_path / "bad_experiments"
    experiments_dir.mkdir()
    (experiments_dir / "bad.json").write_text(json.dumps(data), encoding="utf-8")

    app.dependency_overrides[dependencies.get_experiments_dir] = lambda: experiments_dir
    try:
        response = client.post(
            "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
        )
    finally:
        del app.dependency_overrides[dependencies.get_experiments_dir]

    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "experiment_not_runnable"
    # the underlying exception text (which may include server paths) must never reach the client
    assert "totally_unknown_strategy" not in response.text


def test_run_missing_dataset_returns_422_without_leaking_server_path(
    client: TestClient, tmp_path: Path
) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["dataset_path"] = "test_data/vpn/does_not_exist.json"
    experiments_dir = tmp_path / "bad_experiments"
    experiments_dir.mkdir()
    (experiments_dir / "bad.json").write_text(json.dumps(data), encoding="utf-8")

    app.dependency_overrides[dependencies.get_experiments_dir] = lambda: experiments_dir
    try:
        response = client.post(
            "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
        )
    finally:
        del app.dependency_overrides[dependencies.get_experiments_dir]

    assert response.status_code == 422
    assert response.json()["error"] == "experiment_not_runnable"
    assert str(Path.cwd()) not in response.text


def test_run_unknown_experiment_returns_404_not_403(client: TestClient) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-999999/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 404


def test_run_invalid_execution_context_returns_422(client: TestClient) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "not_a_real_context"}
    )
    assert response.status_code == 422


def test_run_malformed_body_returns_422(client: TestClient) -> None:
    response = client.post("/experiments/ZC-VPN-EXP-001/runs", json={})
    assert response.status_code == 422
