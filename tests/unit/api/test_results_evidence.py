from pathlib import Path

from fastapi.testclient import TestClient

from zeroshield.policies import ExecutionContext
from zeroshield.services.job_store import JobStore
from zeroshield.worker.processor import process_run_job

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"


def _run_vpn(client: TestClient, results_root: Path, jobs_dir: Path) -> dict:
    """Submits via the real API, then processes the job exactly as the worker would -
    process_run_job is the same function the RabbitMQ consume loop calls per message -
    then polls the job via the real API. A full round trip without needing a live broker."""
    submit_response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert submit_response.status_code == 202
    job_id = submit_response.json()["job_id"]

    process_run_job(
        job_id,
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=JobStore(jobs_dir),
    )

    job_response = client.get(f"/jobs/{job_id}")
    assert job_response.status_code == 200
    body = job_response.json()
    assert body["status"] == "completed"
    return body


def test_results_not_found_before_any_run(client: TestClient) -> None:
    response = client.get("/experiments/ZC-VPN-EXP-001/results")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "evidence_not_found"


def test_evidence_not_found_before_any_run(client: TestClient) -> None:
    response = client.get("/experiments/ZC-VPN-EXP-001/evidence")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "evidence_not_found"


def test_results_after_real_run_matches_job_result(
    client: TestClient, results_root: Path, jobs_dir: Path
) -> None:
    job_body = _run_vpn(client, results_root, jobs_dir)
    result = job_body["result"]

    response = client.get("/experiments/ZC-VPN-EXP-001/results")
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["baseline_run_id"] == result["baseline_run_id"]
    assert body["mitigation_run_id"] == result["mitigation_run_id"]
    assert body["total_cases"] == 22
    assert body["mitigation_metrics"]["block_rate"] == result["mitigation_block_rate"]
    assert len(body["limitations"]) >= 1


def test_evidence_after_real_run_is_integrity_verified(
    client: TestClient, results_root: Path, jobs_dir: Path
) -> None:
    job_body = _run_vpn(client, results_root, jobs_dir)
    result = job_body["result"]

    response = client.get("/experiments/ZC-VPN-EXP-001/evidence")
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["evidence_location"] == str(results_root / "ZC-VPN-EXP-001")
    assert body["baseline"]["run_id"] == result["baseline_run_id"]
    assert body["baseline"]["integrity_verified"] is True
    assert body["mitigation"]["run_id"] == result["mitigation_run_id"]
    assert body["mitigation"]["integrity_verified"] is True
    assert body["baseline"]["mode"] == "baseline"
    assert body["mitigation"]["mode"] == "mitigated"


def test_evidence_detects_tampering(client: TestClient, results_root: Path, jobs_dir: Path) -> None:
    job_body = _run_vpn(client, results_root, jobs_dir)
    result = job_body["result"]
    manifest_path = (
        results_root / "ZC-VPN-EXP-001" / result["mitigation_run_id"] / "manifest.json"
    )
    tampered = manifest_path.read_text(encoding="utf-8").replace(
        "strict_schema_canonicalisation_mitigation", "weak_schema_length_baseline"
    )
    manifest_path.write_text(tampered, encoding="utf-8")

    response = client.get("/experiments/ZC-VPN-EXP-001/evidence")
    assert response.status_code == 200
    assert response.json()["mitigation"]["integrity_verified"] is False
