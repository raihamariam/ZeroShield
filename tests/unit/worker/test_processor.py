import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zeroshield.models import ApprovalStatus
from zeroshield.models.enums import RunEventType
from zeroshield.observability.metrics import (
    WORKER_JOB_DURATION_SECONDS,
    WORKER_JOBS_PROCESSED_TOTAL,
)
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import RunEvent, RunRepository
from zeroshield.services.job_store import JobStatus, JobStore
from zeroshield.worker.processor import process_run_job


def _counter_value(counter: object, **labels: str) -> float:
    labelled = counter.labels(**labels)  # type: ignore[attr-defined]
    for family in labelled.collect():
        for sample in family.samples:
            if sample.name.endswith("_total"):
                return sample.value
    return 0.0


def _histogram_observation_count(histogram: object) -> float:
    for family in histogram.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            if sample.name.endswith("_count"):
                return sample.value
    return 0.0

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
VPN_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-VPN-EXP-001.json"
TELECOM_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-TELECOM-EXP-001.json"


def test_process_run_job_vpn_end_to_end(tmp_path: Path) -> None:
    """Integration-level: real orchestration/runner/strategies, no mocking."""
    job_store = JobStore(tmp_path / "jobs")
    results_root = tmp_path / "results"

    process_run_job(
        "JOB-vpn",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=job_store,
    )

    record = job_store.load("JOB-vpn")
    assert record is not None
    assert record.status == JobStatus.COMPLETED
    assert record.result is not None
    assert record.result.total_cases == 22
    assert record.result.mitigation_block_rate == 1.0
    assert record.error is None
    assert (results_root / "ZC-VPN-EXP-001" / "comparison.json").is_file()


def test_process_run_job_telecom_end_to_end(tmp_path: Path) -> None:
    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-telecom",
        "ZC-TELECOM-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
    )
    record = job_store.load("JOB-telecom")
    assert record is not None
    assert record.status == JobStatus.COMPLETED
    assert record.result is not None
    assert record.result.total_cases == 25


def test_process_run_job_denied_by_safety_policy(tmp_path: Path) -> None:
    """Draft VPN experiment under the strict experiment_run context must be denied."""
    job_store = JobStore(tmp_path / "jobs")
    results_root = tmp_path / "results"

    process_run_job(
        "JOB-denied",
        "ZC-VPN-EXP-001",
        ExecutionContext.EXPERIMENT_RUN,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=results_root,
        job_store=job_store,
    )

    record = job_store.load("JOB-denied")
    assert record is not None
    assert record.status == JobStatus.DENIED
    assert record.result is None
    assert record.error is not None
    assert "SAFE-004" in record.error
    # strongest proof: no evidence was ever written, the runner never executed a case
    assert not results_root.exists()


def test_process_run_job_unsafe_configured_experiment_is_denied(tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["weaponised_payloads"] = True
    data["approval_status"] = ApprovalStatus.APPROVED.value
    experiments_dir = tmp_path / "unsafe_experiments"
    experiments_dir.mkdir()
    (experiments_dir / "unsafe.json").write_text(json.dumps(data), encoding="utf-8")

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-unsafe",
        "ZC-VPN-EXP-001",
        ExecutionContext.EXPERIMENT_RUN,
        experiments_dir=experiments_dir,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    record = job_store.load("JOB-unsafe")
    assert record is not None
    assert record.status == JobStatus.DENIED
    assert record.error is not None
    assert "SAFE-003" in record.error


def test_process_run_job_experiment_not_found_marks_failed(tmp_path: Path) -> None:
    job_store = JobStore(tmp_path / "jobs")
    empty_dir = tmp_path / "no_experiments_here"
    empty_dir.mkdir()

    process_run_job(
        "JOB-missing",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=empty_dir,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    record = job_store.load("JOB-missing")
    assert record is not None
    assert record.status == JobStatus.FAILED
    assert record.error is not None
    assert "could not be found" in record.error


def test_process_run_job_unknown_strategy_marks_failed_without_leaking_detail(
    tmp_path: Path,
) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["baseline_strategy"] = "totally_unknown_strategy"
    experiments_dir = tmp_path / "bad_experiments"
    experiments_dir.mkdir()
    (experiments_dir / "bad.json").write_text(json.dumps(data), encoding="utf-8")

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-bad-strategy",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=experiments_dir,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    record = job_store.load("JOB-bad-strategy")
    assert record is not None
    assert record.status == JobStatus.FAILED
    assert record.error is not None
    assert "totally_unknown_strategy" not in record.error


def test_process_run_job_missing_dataset_marks_failed_without_leaking_server_path(
    tmp_path: Path,
) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["dataset_path"] = "test_data/vpn/does_not_exist.json"
    experiments_dir = tmp_path / "bad_experiments"
    experiments_dir.mkdir()
    (experiments_dir / "bad.json").write_text(json.dumps(data), encoding="utf-8")

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-bad-dataset",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=experiments_dir,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    record = job_store.load("JOB-bad-dataset")
    assert record is not None
    assert record.status == JobStatus.FAILED
    assert record.error is not None
    assert str(Path.cwd()) not in record.error


def test_process_run_job_unexpected_error_marks_failed_generically(tmp_path: Path) -> None:
    """A dataset/experiment domain mismatch raises a plain ValueError deep inside
    ExperimentRunner.run() - not PolicyRefusalError or ExperimentServiceError - exercising
    the generic catch-all. The real exception must still never reach the job record."""
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["dataset_path"] = "test_data/telecom/telecom_sip_session_setup_dataset.json"
    experiments_dir = tmp_path / "mismatched_experiments"
    experiments_dir.mkdir()
    (experiments_dir / "mismatched.json").write_text(json.dumps(data), encoding="utf-8")

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-mismatch",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=experiments_dir,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    record = job_store.load("JOB-mismatch")
    assert record is not None
    assert record.status == JobStatus.FAILED
    assert record.error == "an internal error occurred"


def test_process_run_job_preserves_submitted_at_from_existing_record(tmp_path: Path) -> None:
    """Simulates the API having already written a QUEUED record before the worker picks it up."""
    from datetime import UTC, datetime

    from zeroshield.services.job_store import JobRecord

    job_store = JobStore(tmp_path / "jobs")
    original_submitted_at = datetime(2020, 1, 1, tzinfo=UTC)
    job_store.save(
        JobRecord(
            job_id="JOB-preexisting",
            experiment_id="ZC-VPN-EXP-001",
            execution_context=ExecutionContext.LOCAL_UNIT_TEST,
            status=JobStatus.QUEUED,
            submitted_at=original_submitted_at,
            updated_at=original_submitted_at,
        )
    )

    process_run_job(
        "JOB-preexisting",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    record = job_store.load("JOB-preexisting")
    assert record is not None
    assert record.submitted_at == original_submitted_at
    assert record.updated_at > original_submitted_at


def test_process_run_job_completed_increments_operational_metrics(tmp_path: Path) -> None:
    before_count = _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="completed")
    before_observations = _histogram_observation_count(WORKER_JOB_DURATION_SECONDS)

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-metrics-completed",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    assert _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="completed") == before_count + 1
    assert _histogram_observation_count(WORKER_JOB_DURATION_SECONDS) == before_observations + 1


def test_process_run_job_denied_increments_operational_metrics(tmp_path: Path) -> None:
    before_count = _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="denied")

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-metrics-denied",
        "ZC-VPN-EXP-001",
        ExecutionContext.EXPERIMENT_RUN,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    assert _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="denied") == before_count + 1


def test_process_run_job_failed_increments_operational_metrics(tmp_path: Path) -> None:
    before_count = _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="failed")

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-metrics-failed",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=tmp_path / "no_such_experiments_dir",
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    assert _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="failed") == before_count + 1


def test_process_run_job_running_status_does_not_count_as_terminal(tmp_path: Path) -> None:
    """RUNNING is an intermediate status, recorded before the outcome is known - it must
    never be counted as a processed/terminal job."""
    before_completed = _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="running")

    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-metrics-running-check",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
    )

    # "running" is never a valid label value for this counter - it should stay at 0
    assert _counter_value(WORKER_JOBS_PROCESSED_TOTAL, status="running") == before_completed == 0.0


class _RecordingRunRepository(RunRepository):
    """In-memory RunRepository fake for asserting event order/content without a database."""

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
        clock: Any = lambda: datetime.now(UTC),
    ) -> RunEvent:
        event = RunEvent(
            run_id=run_id,
            experiment_id=experiment_id,
            event_type=event_type,
            occurred_at=clock(),
            detail=detail,
        )
        self.events.append(event)
        return event

    def list_events(self, run_id: str) -> list[RunEvent]:
        return [e for e in self.events if e.run_id == run_id]


class _RaisingRunRepository(RunRepository):
    """Simulates Postgres being unreachable - every call raises."""

    def record_event(self, *args: Any, **kwargs: Any) -> RunEvent:
        raise ConnectionError("simulated database outage")

    def list_events(self, run_id: str) -> list[RunEvent]:
        raise ConnectionError("simulated database outage")


def test_process_run_job_records_full_event_lifecycle_on_completion(tmp_path: Path) -> None:
    run_repository = _RecordingRunRepository()
    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-events-completed",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
        run_repository=run_repository,
    )

    event_types = [e.event_type for e in run_repository.list_events("JOB-events-completed")]
    assert event_types == [
        RunEventType.PREPARING,
        RunEventType.SAFETY_CHECK,
        RunEventType.RUNNING_BASELINE,
        RunEventType.RUNNING_MITIGATION,
        RunEventType.ANALYSING,
        RunEventType.GENERATING_EVIDENCE,
        RunEventType.COMPLETED,
    ]
    assert all(e.experiment_id == "ZC-VPN-EXP-001" for e in run_repository.events)


def test_process_run_job_records_denied_event(tmp_path: Path) -> None:
    run_repository = _RecordingRunRepository()
    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-events-denied",
        "ZC-VPN-EXP-001",
        ExecutionContext.EXPERIMENT_RUN,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
        run_repository=run_repository,
    )

    event_types = [e.event_type for e in run_repository.list_events("JOB-events-denied")]
    assert event_types == [RunEventType.PREPARING, RunEventType.SAFETY_CHECK, RunEventType.DENIED]


def test_process_run_job_records_failed_event_for_missing_experiment(tmp_path: Path) -> None:
    run_repository = _RecordingRunRepository()
    job_store = JobStore(tmp_path / "jobs")
    empty_dir = tmp_path / "no_experiments_here"
    empty_dir.mkdir()

    process_run_job(
        "JOB-events-missing",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=empty_dir,
        results_root=tmp_path / "results",
        job_store=job_store,
        run_repository=run_repository,
    )

    event_types = [e.event_type for e in run_repository.list_events("JOB-events-missing")]
    assert event_types == [RunEventType.FAILED]


def test_process_run_job_defaults_to_null_run_repository_when_omitted(tmp_path: Path) -> None:
    """run_repository is fully optional - omitting it must behave exactly as before
    this phase, per V1 compatibility."""
    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-no-repo",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
    )
    record = job_store.load("JOB-no-repo")
    assert record is not None
    assert record.status == JobStatus.COMPLETED


def test_process_run_job_completes_normally_even_if_run_repository_is_unreachable(
    tmp_path: Path,
) -> None:
    """A RunRepository failure (e.g. Postgres down) is auxiliary observability - it
    must never interrupt or alter the actual job outcome, only be logged."""
    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-db-down",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
        run_repository=_RaisingRunRepository(),
    )
    record = job_store.load("JOB-db-down")
    assert record is not None
    assert record.status == JobStatus.COMPLETED
    assert record.result is not None
    assert record.result.total_cases == 22
    assert (tmp_path / "results" / "ZC-VPN-EXP-001" / "comparison.json").is_file()


def test_process_run_job_denial_completes_normally_even_if_run_repository_is_unreachable(
    tmp_path: Path,
) -> None:
    job_store = JobStore(tmp_path / "jobs")
    process_run_job(
        "JOB-db-down-denied",
        "ZC-VPN-EXP-001",
        ExecutionContext.EXPERIMENT_RUN,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
        run_repository=_RaisingRunRepository(),
    )
    record = job_store.load("JOB-db-down-denied")
    assert record is not None
    assert record.status == JobStatus.DENIED
    assert record.error is not None
    assert "SAFE-004" in record.error
