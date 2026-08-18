"""Engine/session-factory construction for the run-lifecycle system-of-record.

Reads DATABASE_URL, mirroring how zeroshield.worker.main.get_rabbitmq_url and
zeroshield.repositories.minio_evidence_repository.default_minio_client read
RABBITMQ_URL/MINIO_*. The default value matches the credentials and
deliberately-non-default host port docker-compose.yml's postgres service
uses (5433, not Postgres's default 5432, for the same reason RabbitMQ/MinIO
use non-default host ports - see docker-compose.yml's top-of-file comment).
"""

import os
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

_DEFAULT_DATABASE_URL = "postgresql+psycopg://zeroshield:zeroshield123@localhost:5433/zeroshield"


def get_database_url() -> str:
    return os.environ.get("DATABASE_URL", _DEFAULT_DATABASE_URL)


def build_engine(database_url: str | None = None) -> Engine:
    return create_engine(database_url or get_database_url(), future=True)


def build_sessionmaker(engine: Engine | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=engine or build_engine(), expire_on_commit=False, future=True)


@lru_cache(maxsize=1)
def get_shared_sessionmaker() -> sessionmaker[Session]:
    """Process-wide singleton sessionmaker/engine (final release
    verification fix) - one Engine per process, with its own bounded
    connection pool, is the standard SQLAlchemy/FastAPI pattern; every
    zeroshield.api.dependencies repository getter previously called
    build_sessionmaker() bare on every dependency resolution, i.e. on every
    single request, each call silently creating a brand-new Engine (and
    therefore a brand-new, additional connection pool on top of every pool
    already created by every previous request). Confirmed, under sustained
    live-stack testing, to exhaust Postgres's max_connections ("FATAL: sorry,
    too many clients already") well within one extended test session - not
    a hypothetical, a reproduced failure. Safe to cache process-wide:
    DATABASE_URL is read once from the environment at process start and
    never changes at runtime. zeroshield.worker.main/intelligence_main are
    unaffected - they already call get_run_repository()/
    get_assurance_repository()/get_audit_repository() exactly once, in
    main(), not per message."""
    return build_sessionmaker()
