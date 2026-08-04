from datetime import UTC, datetime
from pathlib import Path

from zeroshield.policies import ExecutionContext
from zeroshield.services.job_store import JobRecord, JobStatus, JobStore, RunResultSummary


def _record(job_id: str, status: JobStatus = JobStatus.QUEUED, **overrides: object) -> JobRecord:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "job_id": job_id,
        "experiment_id": "ZC-VPN-EXP-001",
        "execution_context": ExecutionContext.LOCAL_UNIT_TEST,
        "status": status,
        "submitted_at": now,
        "updated_at": now,
    }
    defaults.update(overrides)
    return JobRecord.model_validate(defaults)


def test_load_returns_none_for_unknown_job(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "jobs")
    assert store.load("JOB-does-not-exist") is None


def test_save_then_load_round_trips(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "jobs")
    record = _record("JOB-abc123")
    store.save(record)

    loaded = store.load("JOB-abc123")
    assert loaded == record


def test_save_creates_jobs_directory_if_missing(tmp_path: Path) -> None:
    jobs_dir = tmp_path / "nested" / "jobs"
    store = JobStore(jobs_dir)
    store.save(_record("JOB-xyz"))
    assert (jobs_dir / "JOB-xyz.json").is_file()


def test_save_overwrites_existing_record_for_same_job_id(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "jobs")
    store.save(_record("JOB-1", status=JobStatus.QUEUED))
    store.save(_record("JOB-1", status=JobStatus.RUNNING))

    loaded = store.load("JOB-1")
    assert loaded is not None
    assert loaded.status == JobStatus.RUNNING


def test_round_trips_a_completed_record_with_result(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "jobs")
    result = RunResultSummary(
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        total_cases=22,
        baseline_block_rate=0.0,
        mitigation_block_rate=1.0,
        block_rate_improvement=1.0,
        evidence_location="/app/results/ZC-VPN-EXP-001",
    )
    store.save(_record("JOB-done", status=JobStatus.COMPLETED, result=result))

    loaded = store.load("JOB-done")
    assert loaded is not None
    assert loaded.result == result


def test_round_trips_a_denied_record_with_error(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "jobs")
    store.save(_record("JOB-denied", status=JobStatus.DENIED, error="SAFE-004: ..."))

    loaded = store.load("JOB-denied")
    assert loaded is not None
    assert loaded.status == JobStatus.DENIED
    assert loaded.error == "SAFE-004: ..."
