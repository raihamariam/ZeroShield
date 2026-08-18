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

from fastapi import Cookie, Depends, HTTPException, Request

from zeroshield.api.messaging import publish_run_job
from zeroshield.auth.models import Role, User
from zeroshield.experiments import find_experiment
from zeroshield.models import ExperimentDefinition
from zeroshield.repositories import NullRunRepository, RunRepository
from zeroshield.services.job_store import JobStore, RunJobMessage

if TYPE_CHECKING:
    # Type-only: keeps sqlalchemy/httpx/pika/anthropic out of this module's
    # *runtime* import graph for callers that never touch the
    # intelligence/studio/assurance/ai/auth/audit dependencies below - the
    # actual imports happen lazily inside each function body. zeroshield.auth.
    # models (Role/User, imported for real above) is pure-Pydantic and has no
    # such cost, so it is not deferred - FastAPI's own get_type_hints() needs
    # it resolvable at import time wherever CurrentUser/require_role are used.
    from zeroshield.ai.provider import AIProvider
    from zeroshield.ai.research_analyst_service import ResearchAnalystService
    from zeroshield.assurance.repository import AssuranceRepository
    from zeroshield.audit.repository import AuditRepository
    from zeroshield.auth.repository import AuthRepository
    from zeroshield.auth.service import AuthService
    from zeroshield.intelligence.messaging import IntelligenceSyncJobMessage
    from zeroshield.intelligence.repository import VulnerabilityRepository
    from zeroshield.studio.repository import ExperimentVersionRepository

SESSION_COOKIE_NAME = "zeroshield_session"


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

    from zeroshield.db.session import get_shared_sessionmaker
    from zeroshield.repositories.postgres_run_repository import PostgresRunRepository

    return PostgresRunRepository(get_shared_sessionmaker())


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

    from zeroshield.db.session import get_shared_sessionmaker
    from zeroshield.intelligence.repository import VulnerabilityRepository

    return VulnerabilityRepository(get_shared_sessionmaker())


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

    from zeroshield.db.session import get_shared_sessionmaker
    from zeroshield.studio.repository import ExperimentVersionRepository

    return ExperimentVersionRepository(get_shared_sessionmaker())


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
    from zeroshield.db.session import get_shared_sessionmaker

    return AssuranceRepository(get_shared_sessionmaker())


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


# -- Auth / RBAC / audit (V2 Phase 6) ------------------------------------------


def get_request_id(request: Request) -> str | None:
    """Reads the correlation ID zeroshield.api.observability.
    RequestContextMiddleware attached to this request - None only if that
    middleware somehow never ran (never true in the real app; only possible
    in a test that builds a route in isolation)."""
    return getattr(request.state, "request_id", None)


def get_auth_repository() -> "AuthRepository":
    """No no-op fallback, same reasoning as get_vulnerability_repository:
    user/session data (V2 Phase 6) is PostgreSQL-backed, never optional."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise HTTPException(
            status_code=503,
            detail={"error": "auth_unavailable", "detail": "DATABASE_URL is not configured - authentication requires PostgreSQL."},
        )

    from zeroshield.auth.repository import AuthRepository
    from zeroshield.db.session import get_shared_sessionmaker

    return AuthRepository(get_shared_sessionmaker())


def get_audit_repository() -> "AuditRepository":
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise HTTPException(
            status_code=503,
            detail={"error": "audit_unavailable", "detail": "DATABASE_URL is not configured - the audit trail requires PostgreSQL."},
        )

    from zeroshield.audit.repository import AuditRepository
    from zeroshield.db.session import get_shared_sessionmaker

    return AuditRepository(get_shared_sessionmaker())


def get_auth_service(
    auth_repository: Annotated["AuthRepository", Depends(get_auth_repository)],
    audit_repository: Annotated["AuditRepository", Depends(get_audit_repository)],
) -> "AuthService":
    from zeroshield.auth.service import AuthService

    return AuthService(auth_repository, audit_repository)


def get_current_user(
    auth_service: Annotated["AuthService", Depends(get_auth_service)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> User:
    """The one dependency every non-public route requires. 401s (never
    silently treats a missing/expired/invalid session as "no user") on
    anything wrong with the cookie - a route that wants optional auth does
    not exist in this application; see docs/V2_SECURITY.md."""
    if session_token is None:
        raise HTTPException(status_code=401, detail={"error": "not_authenticated", "detail": "no session cookie was presented"})
    user = auth_service.get_user_for_session(session_token)
    if user is None:
        raise HTTPException(
            status_code=401, detail={"error": "not_authenticated", "detail": "session is missing, expired, or invalid"}
        )
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(*roles: Role) -> Callable[..., User]:
    """Returns a dependency that 403s unless current_user.role is one of
    `roles` - every route names the exact roles it allows explicitly (no
    implicit hierarchy), per Step 2's own instruction that "frontend button
    hiding is not security": this is the backend enforcement point, and it
    is the ONLY one - every mutating route in this application depends on
    either this or get_current_user directly, never on nothing."""

    def _check(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "forbidden",
                    "detail": f"role '{current_user.role.value}' is not permitted to perform this action "
                    f"(requires one of: {', '.join(r.value for r in roles)})",
                },
            )
        return current_user

    return _check
