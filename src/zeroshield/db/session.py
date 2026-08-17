"""Engine/session-factory construction for the run-lifecycle system-of-record.

Reads DATABASE_URL, mirroring how zeroshield.worker.main.get_rabbitmq_url and
zeroshield.repositories.minio_evidence_repository.default_minio_client read
RABBITMQ_URL/MINIO_*. The default value matches the credentials and
deliberately-non-default host port docker-compose.yml's postgres service
uses (5433, not Postgres's default 5432, for the same reason RabbitMQ/MinIO
use non-default host ports - see docker-compose.yml's top-of-file comment).
"""

import os

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
