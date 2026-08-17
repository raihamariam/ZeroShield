from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.db.base import Base
from zeroshield.intelligence.repository import VulnerabilityRepository

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"


@pytest.fixture
def assurance_repo() -> AssuranceRepository:
    """In-memory SQLite-backed AssuranceRepository - same portable-SQLAlchemy
    pattern as tests/unit/intelligence/conftest.py's vuln_repo."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AssuranceRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def vuln_repo() -> VulnerabilityRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return VulnerabilityRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))
