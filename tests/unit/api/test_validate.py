from fastapi.testclient import TestClient


def test_validate_vpn_passes_under_local_unit_test(client: TestClient) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/validate", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["safety_passed"] is True
    assert body["overall_valid"] is True
    assert body["dataset_available"] is True
    assert body["safety_reasons"] == []


def test_validate_vpn_denied_under_default_experiment_run_context(client: TestClient) -> None:
    """ZC-VPN-EXP-001 is still draft; the strict execution_context must deny it."""
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/validate", json={"execution_context": "experiment_run"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["safety_passed"] is False
    assert body["overall_valid"] is False
    assert any("SAFE-004" in reason for reason in body["safety_reasons"])


def test_validate_rejects_invalid_execution_context(client: TestClient) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/validate", json={"execution_context": "not_a_real_context"}
    )
    assert response.status_code == 422


def test_validate_rejects_malformed_request_body(client: TestClient) -> None:
    response = client.post("/experiments/ZC-VPN-EXP-001/validate", json={})
    assert response.status_code == 422


def test_validate_rejects_non_json_body(client: TestClient) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/validate",
        content=b"not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
