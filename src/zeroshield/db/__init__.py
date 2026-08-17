"""PostgreSQL system-of-record for run lifecycle state (V2 Platform Foundation
phase). Deliberately separate from zeroshield.models (frozen Pydantic domain
models validated per-run) and zeroshield.repositories.evidence_repository
(evidence object bodies) - this package only persists the *run lifecycle*
(zeroshield.repositories.run_repository.RunRepository), never evidence
content, never a safety decision, never an approval.

Importing this package requires the optional "db" extra (sqlalchemy, alembic,
psycopg). No existing CLI/dashboard/API/worker code path imports it eagerly -
see zeroshield.repositories.postgres_run_repository and
zeroshield.worker.main.get_run_repository for the guarded, DATABASE_URL-gated
import pattern that keeps it optional, consistent with how MinIO/pika are
already optional.
"""

from zeroshield.db.base import Base
from zeroshield.db.session import build_engine, build_sessionmaker, get_database_url

__all__ = ["Base", "build_engine", "build_sessionmaker", "get_database_url"]
