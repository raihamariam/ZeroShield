"""POST /experiments/{id}/runs is asynchronous (Milestone 21): it only validates the
experiment exists, records a QUEUED job, and publishes a message - it never executes
anything itself. Safety denial / unknown-strategy / missing-dataset scenarios are
therefore tested against the worker (tests/unit/worker/test_processor.py) and the
full submit-then-process round trip (test_jobs_integration.py), not here.
"""

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.models.enums import RunEventType
from zeroshield.repositories import RunEvent, RunRepository
from zeroshield.services.job_store import RunJobMessage

REPO_ROOT = Path(__file__).resolve().parents[3]
VPN_EXPERIMENT_PATH = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"


def test_submit_vpn_run_returns_202_with_job_id(
    client: TestClient, published_messages: list[RunJobMessage], jobs_dir: Path
) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 202
    body = response.json()
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["status"] == "queued"
    assert body["job_id"].startswith("JOB-")

    assert len(published_messages) == 1
    assert published_messages[0].job_id == body["job_id"]
    assert published_messages[0].experiment_id == "ZC-VPN-EXP-001"
    assert published_messages[0].execution_context.value == "local_unit_test"

    assert (jobs_dir / f"{body['job_id']}.json").is_file()


def test_submit_telecom_run_returns_202(
    client: TestClient, published_messages: list[RunJobMessage]
) -> None:
    response = client.post(
        "/experiments/ZC-TELECOM-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 202
    assert response.json()["experiment_id"] == "ZC-TELECOM-EXP-001"
    assert len(published_messages) == 1


def test_submit_run_never_executes_or_writes_evidence_synchronously(
    client: TestClient, results_root: Path
) -> None:
    """Submission alone must never run baseline/mitigation - that is the worker's job."""
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 202
    assert not results_root.exists()


def test_submit_run_for_draft_experiment_is_still_accepted_at_submission_time(
    client: TestClient, published_messages: list[RunJobMessage]
) -> None:
    """The API never pre-evaluates SafetyPolicy - only the worker does, when the job
    actually runs. A 202 here is not proof the run is, or will be, allowed."""
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "experiment_run"}
    )
    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    assert published_messages[0].execution_context.value == "experiment_run"


def test_submit_run_unknown_experiment_returns_404(
    client: TestClient, published_messages: list[RunJobMessage]
) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-999999/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 404
    assert published_messages == []


def test_submit_run_invalid_execution_context_returns_422(client: TestClient) -> None:
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "not_a_real_context"}
    )
    assert response.status_code == 422


def test_submit_run_malformed_body_returns_422(client: TestClient) -> None:
    response = client.post("/experiments/ZC-VPN-EXP-001/runs", json={})
    assert response.status_code == 422


def test_submit_run_rejects_unexpected_fields(client: TestClient) -> None:
    """The request schema has no field for strategy/dataset/target overrides - the client
    can only ever reference a registered experiment_id via the URL path."""
    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs",
        json={
            "execution_context": "local_unit_test",
            "baseline_strategy": "arbitrary_injected_strategy",
            "dataset_path": "/etc/passwd",
        },
    )
    assert response.status_code == 422


class _RecordingRunRepository(RunRepository):
    def __init__(self) -> None:
        self.events: list[RunEvent] = []

    def record_event(
        self,
        run_id: str,
        experiment_id: str,
        event_type: RunEventType,
        *,
        execution_context: str | None = None,
        detail: dict[str, Any] | None = None,
        clock: Any = None,
    ) -> RunEvent:
        from datetime import UTC, datetime

        event = RunEvent(
            run_id=run_id,
            experiment_id=experiment_id,
            event_type=event_type,
            occurred_at=datetime.now(UTC),
            detail=detail,
        )
        self.events.append(event)
        return event

    def list_events(self, run_id: str) -> list[RunEvent]:
        return [e for e in self.events if e.run_id == run_id]


class _RaisingRunRepository(RunRepository):
    def record_event(self, *args: Any, **kwargs: Any) -> RunEvent:
        raise ConnectionError("simulated database outage")

    def list_events(self, run_id: str) -> list[RunEvent]:
        raise ConnectionError("simulated database outage")


def test_submit_run_records_queued_event_when_run_repository_configured(
    client: TestClient,
) -> None:
    run_repository = _RecordingRunRepository()
    app.dependency_overrides[dependencies.get_run_repository] = lambda: run_repository
    try:
        response = client.post(
            "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
        )
        assert response.status_code == 202
        job_id = response.json()["job_id"]
        assert [e.event_type for e in run_repository.list_events(job_id)] == [RunEventType.QUEUED]
    finally:
        del app.dependency_overrides[dependencies.get_run_repository]


def test_submit_run_still_succeeds_when_run_repository_is_unreachable(client: TestClient) -> None:
    """A Postgres outage must never block job submission - QUEUED-event recording
    is best-effort auxiliary observability, not a precondition for queuing."""
    app.dependency_overrides[dependencies.get_run_repository] = lambda: _RaisingRunRepository()
    try:
        response = client.post(
            "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
        )
        assert response.status_code == 202
        assert response.json()["status"] == "queued"
    finally:
        del app.dependency_overrides[dependencies.get_run_repository]
