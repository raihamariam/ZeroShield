import pytest
from fastapi.testclient import TestClient


def test_health_returns_healthy(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "zeroshield"}


def test_system_status_reports_real_dependency_state(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No real Postgres/RabbitMQ/MinIO is configured in this test environment - the
    route must report that honestly (available=False with a real reason) rather than
    fabricate a green status. RABBITMQ_URL is pinned to an address nothing listens on
    so the assertion is deterministic regardless of what's running on the dev machine."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("RABBITMQ_URL", "amqp://guest:guest@127.0.0.1:1/")
    monkeypatch.delenv("ZEROSHIELD_EVIDENCE_BACKEND", raising=False)

    response = client.get("/system/status")
    assert response.status_code == 200
    deps = {d["name"]: d for d in response.json()["dependencies"]}

    assert deps["api"]["available"] is True

    assert deps["database"]["available"] is False
    assert "DATABASE_URL" in deps["database"]["detail"]

    assert deps["rabbitmq"]["available"] is False

    assert deps["worker"]["available"] is False
    assert "rabbitmq is unreachable" in deps["worker"]["detail"]

    assert deps["minio"]["available"] is False
    assert "ZEROSHIELD_EVIDENCE_BACKEND" in deps["minio"]["detail"]

    for dep in deps.values():
        assert dep["checked_at"]
