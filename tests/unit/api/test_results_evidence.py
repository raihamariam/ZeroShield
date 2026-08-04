from pathlib import Path

from fastapi.testclient import TestClient


def _run_vpn(client: TestClient) -> dict:
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 200
    return response.json()


def test_results_not_found_before_any_run(client: TestClient) -> None:
    response = client.get("/experiments/ZC-VPN-EXP-001/results")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "evidence_not_found"


def test_evidence_not_found_before_any_run(client: TestClient) -> None:
    response = client.get("/experiments/ZC-VPN-EXP-001/evidence")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "evidence_not_found"


def test_results_after_real_run_matches_run_response(client: TestClient) -> None:
    run_body = _run_vpn(client)

    response = client.get("/experiments/ZC-VPN-EXP-001/results")
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["baseline_run_id"] == run_body["baseline_run_id"]
    assert body["mitigation_run_id"] == run_body["mitigation_run_id"]
    assert body["total_cases"] == 22
    assert body["mitigation_metrics"]["block_rate"] == run_body["key_metrics"]["mitigation_block_rate"]
    assert len(body["limitations"]) >= 1


def test_evidence_after_real_run_is_integrity_verified(client: TestClient, results_root: Path) -> None:
    run_body = _run_vpn(client)

    response = client.get("/experiments/ZC-VPN-EXP-001/evidence")
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["evidence_location"] == str(results_root / "ZC-VPN-EXP-001")
    assert body["baseline"]["run_id"] == run_body["baseline_run_id"]
    assert body["baseline"]["integrity_verified"] is True
    assert body["mitigation"]["run_id"] == run_body["mitigation_run_id"]
    assert body["mitigation"]["integrity_verified"] is True
    assert body["baseline"]["mode"] == "baseline"
    assert body["mitigation"]["mode"] == "mitigated"


def test_evidence_detects_tampering(client: TestClient, results_root: Path) -> None:
    run_body = _run_vpn(client)
    manifest_path = (
        results_root / "ZC-VPN-EXP-001" / run_body["mitigation_run_id"] / "manifest.json"
    )
    tampered = manifest_path.read_text(encoding="utf-8").replace(
        "strict_schema_canonicalisation_mitigation", "weak_schema_length_baseline"
    )
    manifest_path.write_text(tampered, encoding="utf-8")

    response = client.get("/experiments/ZC-VPN-EXP-001/evidence")
    assert response.status_code == 200
    assert response.json()["mitigation"]["integrity_verified"] is False
