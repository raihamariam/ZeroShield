from fastapi.testclient import TestClient


def test_list_experiments_finds_vpn_and_telecom(client: TestClient) -> None:
    response = client.get("/experiments")
    assert response.status_code == 200
    body = response.json()
    ids = {e["experiment_id"] for e in body["experiments"]}
    assert "ZC-VPN-EXP-001" in ids
    assert "ZC-TELECOM-EXP-001" in ids
    for entry in body["experiments"]:
        assert set(entry) == {"experiment_id", "title", "domain", "safety_level", "approval_status"}


def test_get_vpn_experiment_detail(client: TestClient) -> None:
    response = client.get("/experiments/ZC-VPN-EXP-001")
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["domain"] == "VPN"
    assert body["baseline_strategy"] == "weak_schema_length_baseline"
    assert body["mitigation_strategy"] == "strict_schema_canonicalisation_mitigation"
    assert len(body["related_cves"]) >= 1
    assert body["related_cves"][0]["cve_id"].startswith("CVE-")
    for field in (
        "title",
        "description",
        "failure_pattern",
        "root_cause",
        "vendor_mitigation",
        "mitigation_gap",
        "research_question",
        "hypothesis",
        "safety_level",
        "approval_status",
    ):
        assert body[field]


def test_get_telecom_experiment_detail(client: TestClient) -> None:
    response = client.get("/experiments/ZC-TELECOM-EXP-001")
    assert response.status_code == 200
    body = response.json()
    assert body["experiment_id"] == "ZC-TELECOM-EXP-001"
    assert body["domain"] == "TELECOM"
    assert body["baseline_strategy"] == "weak_mandatory_field_state_baseline"
    assert body["mitigation_strategy"] == "strict_grammar_state_machine_mitigation"


def test_get_unknown_experiment_returns_404(client: TestClient) -> None:
    response = client.get("/experiments/ZC-VPN-EXP-999999")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "experiment_not_found"


def test_path_traversal_attempt_in_experiment_id_is_rejected(client: TestClient) -> None:
    response = client.get("/experiments/..%2F..%2F..%2Fetc%2Fpasswd")
    assert response.status_code == 404
    # must never resolve to a real file's content
    assert "root:" not in response.text


def test_path_traversal_without_extra_slashes_falls_through_to_lookup_and_404(
    client: TestClient,
) -> None:
    # a traversal-shaped id with no slash still can't equal any real, validated experiment_id
    response = client.get("/experiments/..")
    assert response.status_code == 404


def test_validate_and_run_also_reject_unknown_experiment_with_404(client: TestClient) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-999999/validate", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 404
    response = client.post(
        "/experiments/ZC-VPN-EXP-999999/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 404
