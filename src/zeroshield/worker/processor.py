"""Pure job-processing logic: given a queued job's identifiers, executes it and
records the outcome. Deliberately independent of RabbitMQ so it is directly
testable without a broker - main.py's consume loop is the only thing that
knows about messaging, and it just calls process_run_job() per message.

Only calls into the existing zeroshield.services.experiment_service - no
safety, strategy, orchestration, or metric logic is duplicated here. The
safety gate inside ExperimentRunner.run() (via experiment_service.run_experiment)
is the sole point where SafetyPolicy is evaluated; it is never bypassed here.
"""

import logging
import time
from datetime import UTC, datetime
from pathlib import Path

from zeroshield.experiments import find_experiment
from zeroshield.observability.metrics import (
    WORKER_JOB_DURATION_SECONDS,
    WORKER_JOBS_PROCESSED_TOTAL,
)
from zeroshield.policies import ExecutionContext
from zeroshield.runners import PolicyRefusalError
from zeroshield.services import experiment_service
from zeroshield.services.experiment_service import ExperimentServiceError
from zeroshield.services.job_store import JobRecord, JobStatus, JobStore, RunResultSummary

logger = logging.getLogger("zeroshield.worker")

_TERMINAL_STATUSES = frozenset({JobStatus.COMPLETED, JobStatus.DENIED, JobStatus.FAILED})


def process_run_job(
    job_id: str,
    experiment_id: str,
    execution_context: ExecutionContext,
    *,
    experiments_dir: Path,
    results_root: Path,
    job_store: JobStore,
) -> None:
    existing = job_store.load(job_id)
    submitted_at = existing.submitted_at if existing is not None else datetime.now(UTC)
    started_processing = time.perf_counter()

    def _record(status: JobStatus, **fields: object) -> None:
        job_store.save(
            JobRecord.model_validate(
                {
                    "job_id": job_id,
                    "experiment_id": experiment_id,
                    "execution_context": execution_context,
                    "status": status,
                    "submitted_at": submitted_at,
                    "updated_at": datetime.now(UTC),
                    **fields,
                }
            )
        )
        if status in _TERMINAL_STATUSES:
            WORKER_JOBS_PROCESSED_TOTAL.labels(status=status.value).inc()
            WORKER_JOB_DURATION_SECONDS.observe(time.perf_counter() - started_processing)

    _record(JobStatus.RUNNING)

    experiment = find_experiment(experiments_dir, experiment_id)
    if experiment is None:
        _record(
            JobStatus.FAILED,
            error=f"experiment '{experiment_id}' could not be found when the job started",
        )
        return

    try:
        summary = experiment_service.run_experiment(
            experiment, execution_context=execution_context, results_root=results_root
        )
    except PolicyRefusalError as exc:
        _record(JobStatus.DENIED, error="; ".join(exc.decision.reasons) or "denied by safety policy")
        return
    except ExperimentServiceError as exc:
        # exc's message may include server-side absolute filesystem paths (it is shared
        # with the CLI/dashboard, where that is useful); never persist it verbatim, since
        # it is readable by any API client via GET /jobs/{job_id}.
        logger.warning("job %s not runnable: %s", job_id, exc)
        _record(
            JobStatus.FAILED,
            error="the experiment's configured dataset or processing strategy could not be "
            "resolved on this server.",
        )
        return
    except Exception:
        logger.exception("unhandled error processing job %s", job_id)
        _record(JobStatus.FAILED, error="an internal error occurred")
        return

    comparison = summary.comparison_report
    _record(
        JobStatus.COMPLETED,
        result=RunResultSummary(
            baseline_run_id=comparison.baseline_run_id,
            mitigation_run_id=comparison.mitigation_run_id,
            total_cases=comparison.total_cases,
            baseline_block_rate=comparison.baseline_metrics.block_rate,
            mitigation_block_rate=comparison.mitigation_metrics.block_rate,
            block_rate_improvement=comparison.block_rate_improvement,
            evidence_location=str(summary.results_dir),
        ),
    )
