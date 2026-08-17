"""Shared FastAPI dependencies: data-directory resolution and experiment lookup.

get_experiment resolves a path parameter against the set of already-discovered,
already-validated experiment IDs (from experiment_service.list_experiments) and
returns the validated ExperimentDefinition, never the raw client-supplied
string. Every route uses the returned experiment.experiment_id for any
filesystem access - the raw path parameter is only ever compared for
equality against known-good IDs, never used to build a path. This is what
prevents path traversal via the experiment_id path parameter, without
needing a duplicated ID-pattern check here.
"""

import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, HTTPException

from zeroshield.api.messaging import publish_run_job
from zeroshield.experiments import find_experiment
from zeroshield.models import ExperimentDefinition
from zeroshield.repositories import NullRunRepository, RunRepository
from zeroshield.services.job_store import JobStore, RunJobMessage

if TYPE_CHECKING:
    # Type-only: keeps sqlalchemy/httpx/pika/anthropic out of this module's
    # *runtime* import graph for callers that never touch the
    # intelligence/studio/assurance/ai dependencies below - the actual
    # imports happen lazily inside each function body.
    from zeroshield.ai.provider import AIProvider
    from zeroshield.ai.research_analyst_service import ResearchAnalystService
    from zeroshield.assurance.repository import AssuranceRepository
    from zeroshield.intelligence.messaging import IntelligenceSyncJobMessage
    from zeroshield.intelligence.repository import VulnerabilityRepository
    from zeroshield.studio.repository import ExperimentVersionRepository


def get_experiments_dir() -> Path:
    return Path.cwd() / "experiments"


def get_results_root() -> Path:
    return Path.cwd() / "results"


def get_jobs_dir() -> Path:
    return Path.cwd() / "jobs"


def get_job_store(jobs_dir: Annotated[Path, Depends(get_jobs_dir)]) -> JobStore:
    return JobStore(jobs_dir)


def get_rabbitmq_url() -> str:
    return os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")


def get_publisher(
    rabbitmq_url: Annotated[str, Depends(get_rabbitmq_url)],
) -> Callable[[RunJobMessage], None]:
    def publish(message: RunJobMessage) -> None:
        publish_run_job(message, rabbitmq_url=rabbitmq_url)

    return publish


def get_run_repository() -> RunRepository:
    """Builds a PostgresRunRepository if DATABASE_URL is configured, else the
    no-op NullRunRepository - mirrors zeroshield.worker.main.get_run_repository.
    The sqlalchemy/psycopg import is local/guarded so the "db" extra stays
    optional when DATABASE_URL is unset."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        return NullRunRepository()

    from zeroshield.db.session import build_sessionmaker
    from zeroshield.repositories.postgres_run_repository import PostgresRunRepository

    return PostgresRunRepository(build_sessionmaker())


def get_vulnerability_repository() -> "VulnerabilityRepository":
    """Unlike get_run_repository, there is no no-op fallback here: the
    threat-intelligence system of record IS PostgreSQL (Step 1) - without
    DATABASE_URL, every /vulnerabilities, /priority-queue, /sources and
    /intelligence/* route fails fast with a clear 503 rather than silently
    returning empty/fake data."""
    from fastapi import HTTPException

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "intelligence_unavailable",
                "detail": "DATABASE_URL is not configured - the threat-intelligence system of "
                "record requires PostgreSQL.",
            },
        )

    from zeroshield.db.session import build_sessionmaker
    from zeroshield.intelligence.repository import VulnerabilityRepository

    return VulnerabilityRepository(build_sessionmaker())


def get_intelligence_publisher(
    rabbitmq_url: Annotated[str, Depends(get_rabbitmq_url)],
) -> "Callable[[IntelligenceSyncJobMessage], None]":
    from zeroshield.intelligence.messaging import publish_sync_job

    def publish(message: "IntelligenceSyncJobMessage") -> None:
        publish_sync_job(message, rabbitmq_url=rabbitmq_url)

    return publish


def get_experiment_version_repository() -> "ExperimentVersionRepository":
    """No no-op fallback, same reasoning as get_vulnerability_repository:
    Experiment Studio's versioned drafts/approvals are PostgreSQL-backed."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "studio_unavailable",
                "detail": "DATABASE_URL is not configured - Experiment Studio requires PostgreSQL.",
            },
        )

    from zeroshield.db.session import build_sessionmaker
    from zeroshield.studio.repository import ExperimentVersionRepository

    return ExperimentVersionRepository(build_sessionmaker())


def get_assurance_repository() -> "AssuranceRepository":
    """No no-op fallback, same reasoning as get_vulnerability_repository:
    control/asset/revalidation history (V2 Phase 5) is PostgreSQL-backed."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "assurance_unavailable",
                "detail": "DATABASE_URL is not configured - AI & Continuous Assurance requires PostgreSQL.",
            },
        )

    from zeroshield.assurance.repository import AssuranceRepository
    from zeroshield.db.session import build_sessionmaker

    return AssuranceRepository(build_sessionmaker())


def get_ai_provider() -> "AIProvider":
    from zeroshield.ai.config import resolve_ai_provider

    return resolve_ai_provider()


def get_research_analyst_service(
    provider: Annotated["AIProvider", Depends(get_ai_provider)],
) -> "ResearchAnalystService":
    from zeroshield.ai.research_analyst_service import ResearchAnalystService

    return ResearchAnalystService(provider)


def get_experiment(
    experiment_id: str,
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
) -> ExperimentDefinition:
    experiment = find_experiment(experiments_dir, experiment_id)
    if experiment is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "experiment_not_found",
                "detail": f"no experiment with id '{experiment_id}'",
            },
        )
    return experiment
