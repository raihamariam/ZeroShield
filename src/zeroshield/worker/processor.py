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
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zeroshield.audit.models import Action
from zeroshield.experiments import find_experiment
from zeroshield.models.enums import RunEventType
from zeroshield.observability.metrics import (
    WORKER_JOB_DURATION_SECONDS,
    WORKER_JOBS_PROCESSED_TOTAL,
)
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import NullRunRepository, RunRepository
from zeroshield.runners import PolicyRefusalError
from zeroshield.services import experiment_service
from zeroshield.services.experiment_service import ExperimentServiceError
from zeroshield.services.job_store import JobRecord, JobStatus, JobStore, RunResultSummary

logger = logging.getLogger("zeroshield.worker")


def _record_control_validation(assurance_repository: object, experiment: Any, summary: Any) -> None:
    """Best-effort, auxiliary observability - like _emit() above, a failure
    here (e.g. Postgres unreachable) must never affect job outcome, only be
    logged. Guarded/lazy imports keep zeroshield.assurance (and its
    zeroshield.templates/domain_packs dependency) out of the worker's
    import graph when no assurance_repository is configured."""
    try:
        from zeroshield.assurance.control_binding import bind_experiment_to_control
        from zeroshield.assurance.models import ControlValidation
        from zeroshield.verdict import compute_verdict

        comparison = summary.comparison_report
        binding = bind_experiment_to_control(assurance_repository, experiment)  # type: ignore[arg-type]
        verdict = compute_verdict(comparison)
        m = comparison.mitigation_metrics
        assurance_repository.record_validation(  # type: ignore[attr-defined]
            ControlValidation(
                validation_id=f"VAL-{uuid.uuid4().hex}",
                control_id=binding.control.control_id,
                version_id=binding.version.version_id,
                experiment_id=experiment.experiment_id,
                baseline_run_id=comparison.baseline_run_id,
                mitigation_run_id=comparison.mitigation_run_id,
                total_cases=comparison.total_cases,
                block_rate_improvement=comparison.block_rate_improvement,
                false_positive_rate=m.false_positive_rate,
                false_negative_rate=m.false_negative_rate,
                valid_acceptance_rate=m.valid_acceptance_rate,
                parser_reach_rate=m.parser_reach_rate,
                latency_overhead_ms=comparison.latency_overhead_ms,
                verdict_label=verdict.label.value,
                validated_at=datetime.now(UTC),
            )
        )
    except Exception:
        logger.warning(
            "failed to record control validation for experiment %s", experiment.experiment_id, exc_info=True
        )

_TERMINAL_STATUSES = frozenset({JobStatus.COMPLETED, JobStatus.DENIED, JobStatus.FAILED})


def _audit(
    audit_repository: object | None,
    *,
    action: str,
    target_type: str,
    target_id: str,
    submitted_by_user_id: str | None,
    submitted_by_username: str | None,
    metadata: dict[str, Any],
) -> None:
    """Best-effort, auxiliary - like _record_control_validation above, an
    audit-write failure must never affect job outcome, only be logged.
    `audit_repository` is typed `object` for the same lazy-import reason as
    `assurance_repository` (see process_run_job's own docstring). If the job
    carries no submitter identity (an older queued message, or a caller
    that predates V2 Phase 6 auth), the event is still written with a null
    actor rather than skipped - an audit trail with an unattributed event is
    still more complete than a missing one."""
    if audit_repository is None:
        return
    try:
        audit_repository.record(  # type: ignore[attr-defined]
            actor_user_id=submitted_by_user_id, actor_username=submitted_by_username, actor_role=None,
            action=action, target_type=target_type, target_id=target_id, request_id=None, metadata=metadata,
        )
    except Exception:
        logger.warning("failed to record audit event %s for %s %s", action, target_type, target_id, exc_info=True)


def process_run_job(
    job_id: str,
    experiment_id: str,
    execution_context: ExecutionContext,
    *,
    experiments_dir: Path,
    results_root: Path,
    job_store: JobStore,
    run_repository: RunRepository | None = None,
    assurance_repository: object | None = None,
    audit_repository: object | None = None,
    submitted_by_user_id: str | None = None,
    submitted_by_username: str | None = None,
) -> None:
    """`assurance_repository`/`audit_repository`, when provided, are a
    zeroshield.assurance.repository.AssuranceRepository /
    zeroshield.audit.repository.AuditRepository - typed `object` here
    (rather than imported at module level) so importing this module never
    requires the "db"/assurance/audit dependency chain; see
    _record_control_validation's/_audit's own guarded usage. All optional
    and additive: omitting them leaves job processing byte-for-byte
    identical to before Phases 5/6."""
    existing = job_store.load(job_id)
    submitted_at = existing.submitted_at if existing is not None else datetime.now(UTC)
    started_processing = time.perf_counter()
    run_repository = run_repository or NullRunRepository()

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

    def _emit(event_type: RunEventType, detail: dict[str, Any] | None = None) -> None:
        # RunRepository is an auxiliary system-of-record, never a safety
        # authority - a recording failure (e.g. Postgres unreachable) must
        # never interrupt or alter job processing, only be logged.
        try:
            run_repository.record_event(
                job_id, experiment_id, event_type,
                execution_context=execution_context.value, detail=detail,
            )
        except Exception:
            logger.warning(
                "failed to record run event %s for job %s", event_type.value, job_id, exc_info=True
            )

    _record(JobStatus.RUNNING)

    experiment = find_experiment(experiments_dir, experiment_id)
    if experiment is None:
        _record(
            JobStatus.FAILED,
            error=f"experiment '{experiment_id}' could not be found when the job started",
        )
        _emit(RunEventType.FAILED, {"reason": "experiment_not_found"})
        return

    try:
        summary = experiment_service.run_experiment(
            experiment,
            execution_context=execution_context,
            results_root=results_root,
            event_sink=_emit,
        )
    except PolicyRefusalError as exc:
        _record(JobStatus.DENIED, error="; ".join(exc.decision.reasons) or "denied by safety policy")
        _emit(RunEventType.DENIED, {"reasons": exc.decision.reasons})
        _audit(
            audit_repository, action=Action.RUN_DENIED, target_type="job", target_id=job_id,
            submitted_by_user_id=submitted_by_user_id, submitted_by_username=submitted_by_username,
            metadata={"experiment_id": experiment_id, "reasons": exc.decision.reasons},
        )
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
        _emit(RunEventType.FAILED, {"reason": "service_error"})
        _audit(
            audit_repository, action=Action.RUN_FAILED, target_type="job", target_id=job_id,
            submitted_by_user_id=submitted_by_user_id, submitted_by_username=submitted_by_username,
            metadata={"experiment_id": experiment_id, "reason": "service_error"},
        )
        return
    except Exception:
        logger.exception("unhandled error processing job %s", job_id)
        _record(JobStatus.FAILED, error="an internal error occurred")
        _emit(RunEventType.FAILED, {"reason": "internal_error"})
        _audit(
            audit_repository, action=Action.RUN_FAILED, target_type="job", target_id=job_id,
            submitted_by_user_id=submitted_by_user_id, submitted_by_username=submitted_by_username,
            metadata={"experiment_id": experiment_id, "reason": "internal_error"},
        )
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
    _emit(RunEventType.COMPLETED, {"total_cases": comparison.total_cases})
    _audit(
        audit_repository, action=Action.EVIDENCE_CREATED, target_type="experiment", target_id=experiment_id,
        submitted_by_user_id=submitted_by_user_id, submitted_by_username=submitted_by_username,
        metadata={
            "baseline_run_id": comparison.baseline_run_id, "mitigation_run_id": comparison.mitigation_run_id,
            "total_cases": comparison.total_cases,
        },
    )

    if assurance_repository is not None:
        _record_control_validation(assurance_repository, experiment, summary)
