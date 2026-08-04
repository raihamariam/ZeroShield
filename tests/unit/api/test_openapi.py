from fastapi.testclient import TestClient


def test_docs_ui_is_served(client: TestClient) -> None:
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger" in response.text.lower()


def test_openapi_schema_lists_all_endpoints(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = set(response.json()["paths"])
    assert paths == {
        "/health",
        "/experiments",
        "/experiments/{experiment_id}",
        "/experiments/{experiment_id}/validate",
        "/experiments/{experiment_id}/runs",
        "/experiments/{experiment_id}/results",
        "/experiments/{experiment_id}/evidence",
    }
