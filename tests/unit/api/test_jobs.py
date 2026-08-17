from pathlib import Path

from fastapi.testclient import TestClient

from zeroshield.policies import ExecutionContext
from zeroshield.services.job_store import JobStore
from zeroshield.worker.processor import process_run_job

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"


def test_get_unknown_job_returns_404(client: TestClient) -> None:
    response = client.get("/jobs/JOB-" + "0" * 32)
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "job_not_found"


def test_get_job_with_path_traversal_id_is_rejected_before_filesystem_access(
    client: TestClient,
) -> None:
    """job_id is used directly to build a filesystem path in JobStore. A slash-containing
    traversal attempt doesn't match the single-segment /jobs/{job_id} route at all, so
    Starlette's own router 404s it before any of my code runs."""
    response = client.get("/jobs/..%2F..%2F..%2Fetc%2Fpasswd")
    assert response.status_code == 404
    assert "root:" not in response.text


def test_get_job_with_wrong_shape_id_returns_422(client: TestClient) -> None:
    response = client.get("/jobs/not-a-valid-job-id")
    assert response.status_code == 422


def test_get_job_with_right_prefix_wrong_shape_id_returns_422(client: TestClient) -> None:
    """A single-segment id that reaches the route (no slash to trip up routing, unlike
    the "..%2F..." case above) but doesn't match the server-generated hex shape exercises
    the Path(pattern=...) rejection specifically, not just Starlette's router. (A literal
    ".." segment is normalised away by URL path resolution before it even reaches routing,
    so it 404s the same way the slash-containing case does - even safer than this check.)"""
    response = client.get("/jobs/JOB-not-actually-hex")
    assert response.status_code == 422


def test_submit_then_poll_shows_queued_before_worker_picks_it_up(client: TestClient) -> None:
    submit_response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    job_id = submit_response.json()["job_id"]

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["job_id"] == job_id
    assert body["experiment_id"] == "ZC-VPN-EXP-001"
    assert body["execution_context"] == "local_unit_test"
    assert body["status"] == "queued"
    assert body["result"] is None
    assert body["error"] is None


def test_full_round_trip_vpn_run_completes(
    client: TestClient, results_root: Path, jobs_dir: Path
) -> None:
    """Submit via the API, process exactly as the worker would, poll via the API."""
    submit_response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    job_id = submit_response.json()["job_id"]

    process_run_job(
        job_id,
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=JobStore(jobs_dir),
    )

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["result"]["total_cases"] == 22
    assert body["result"]["mitigation_block_rate"] == 1.0
    assert body["error"] is None


def test_full_round_trip_denied_run_shows_denied_with_reason(
    client: TestClient, results_root: Path, jobs_dir: Path
) -> None:
    """ZC-VPN-EXP-001 is still draft; the strict execution_context must end in DENIED,
    visible to the polling client, with zero evidence ever written."""
    submit_response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "experiment_run"}
    )
    job_id = submit_response.json()["job_id"]

    process_run_job(
        job_id,
        "ZC-VPN-EXP-001",
        ExecutionContext.EXPERIMENT_RUN,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=JobStore(jobs_dir),
    )

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "denied"
    assert body["result"] is None
    assert "SAFE-004" in body["error"]
    assert not results_root.exists()


def test_list_jobs_is_empty_when_none_submitted(client: TestClient) -> None:
    response = client.get("/jobs")
    assert response.status_code == 200
    assert response.json() == {"jobs": []}


def test_list_jobs_shows_most_recent_first_and_supports_status_filter(
    client: TestClient, results_root: Path, jobs_dir: Path
) -> None:
    vpn_job_id = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    ).json()["job_id"]
    telecom_job_id = client.post(
        "/experiments/ZC-TELECOM-EXP-001/runs", json={"execution_context": "local_unit_test"}
    ).json()["job_id"]

    process_run_job(
        telecom_job_id,
        "ZC-TELECOM-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=JobStore(jobs_dir),
    )

    all_jobs = client.get("/jobs").json()["jobs"]
    assert [j["job_id"] for j in all_jobs] == [telecom_job_id, vpn_job_id]

    queued_only = client.get("/jobs", params={"status": "queued"}).json()["jobs"]
    assert [j["job_id"] for j in queued_only] == [vpn_job_id]

    completed_only = client.get("/jobs", params={"status": "completed"}).json()["jobs"]
    assert [j["job_id"] for j in completed_only] == [telecom_job_id]


def test_get_events_for_unknown_job_returns_404(client: TestClient) -> None:
    response = client.get("/jobs/" + "JOB-" + "0" * 32 + "/events")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "job_not_found"


def test_get_events_for_wrong_shape_id_returns_422(client: TestClient) -> None:
    response = client.get("/jobs/not-a-valid-job-id/events")
    assert response.status_code == 422


def test_events_stream_for_completed_job_degrades_honestly_without_database_url(
    client: TestClient, results_root: Path, jobs_dir: Path
) -> None:
    """No DATABASE_URL is configured in the test environment, so get_run_repository
    returns NullRunRepository - list_events is always []. The stream must still
    terminate immediately (the job is already completed) and report the real
    JobStore status, never a fabricated per-stage RunEvent trail."""
    job_id = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    ).json()["job_id"]
    process_run_job(
        job_id,
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=JobStore(jobs_dir),
    )

    response = client.get(f"/jobs/{job_id}/events")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: job_terminal" in response.text
    assert '"job_status": "completed"' in response.text
    assert "event: run_event" not in response.text


def test_full_round_trip_telecom_run_completes(
    client: TestClient, results_root: Path, jobs_dir: Path
) -> None:
    submit_response = client.post(
        "/experiments/ZC-TELECOM-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    job_id = submit_response.json()["job_id"]

    process_run_job(
        job_id,
        "ZC-TELECOM-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=JobStore(jobs_dir),
    )

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["result"]["total_cases"] == 25
