"""End-to-end run-lifecycle recording against a REAL PostgreSQL database, run
through the real Alembic migration - not the in-memory SQLite used everywhere
else in the test suite (tests/unit/repositories/test_run_repository.py).
Mirrors tests/integration/test_api_worker_real_broker.py's opt-in pattern for
RabbitMQ: skipped by default, and deliberately has no default host/port to
fall back to, for the same reason documented there (an earlier version of
that test silently connected to an unrelated broker already using the
standard port on the development machine).

Run with:
    docker compose up -d postgres
    # postgres's port is host-exposed on 5433 (see docker-compose.yml)
    ZEROSHIELD_E2E_POSTGRES_URL="postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield" \
        pytest tests/integration/test_worker_postgres_real_db.py
"""

import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from zeroshield.policies import ExecutionContext
from zeroshield.repositories.postgres_run_repository import PostgresRunRepository
from zeroshield.services.job_store import JobStatus, JobStore
from zeroshield.worker.processor import process_run_job

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"

_POSTGRES_URL = os.environ.get("ZEROSHIELD_E2E_POSTGRES_URL")


def _reachable(url: str) -> bool:
    parsed = urlparse(url)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=1.5):
            return True
    except OSError:
        return False


_skip_reason = (
    "Set ZEROSHIELD_E2E_POSTGRES_URL to run this test against a real Postgres you control "
    "(e.g. postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield after "
    "`docker compose up -d postgres`). Deliberately does not fall back to any default "
    "host/port, to avoid silently connecting to an unrelated database on this machine."
)
if _POSTGRES_URL is not None and not _reachable(_POSTGRES_URL):
    _skip_reason = f"ZEROSHIELD_E2E_POSTGRES_URL is set but not reachable: {_POSTGRES_URL}"
    _POSTGRES_URL = None

pytestmark = pytest.mark.skipif(_POSTGRES_URL is None, reason=_skip_reason)


@pytest.fixture
def migrated_engine():  # type: ignore[no-untyped-def]
    """Runs the real alembic upgrade head / downgrade base against the target
    database, proving 0001_create_runs_and_run_events.py actually applies -
    not just that Base.metadata matches it in-process (see tests/unit/db)."""
    assert _POSTGRES_URL is not None
    alembic_cfg = Config(str(REPO_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    os.environ["DATABASE_URL"] = _POSTGRES_URL
    try:
        command.upgrade(alembic_cfg, "head")
        engine = create_engine(_POSTGRES_URL, future=True)
        yield engine
        engine.dispose()
        command.downgrade(alembic_cfg, "base")
    finally:
        del os.environ["DATABASE_URL"]


def test_alembic_migration_creates_expected_tables(migrated_engine) -> None:  # type: ignore[no-untyped-def]
    with migrated_engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        }
    assert {"runs", "run_events"}.issubset(tables)


def test_process_run_job_persists_full_lifecycle_to_real_postgres(
    migrated_engine, tmp_path: Path  # type: ignore[no-untyped-def]
) -> None:
    run_repository = PostgresRunRepository(
        sessionmaker(bind=migrated_engine, expire_on_commit=False, future=True)
    )
    job_store = JobStore(tmp_path / "jobs")

    process_run_job(
        "JOB-e2e-postgres",
        "ZC-VPN-EXP-001",
        ExecutionContext.LOCAL_UNIT_TEST,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
        run_repository=run_repository,
    )

    record = job_store.load("JOB-e2e-postgres")
    assert record is not None
    assert record.status == JobStatus.COMPLETED

    events = run_repository.list_events("JOB-e2e-postgres")
    assert [e.event_type.value for e in events] == [
        "preparing",
        "safety_check",
        "running_baseline",
        "running_mitigation",
        "analysing",
        "generating_evidence",
        "completed",
    ]
