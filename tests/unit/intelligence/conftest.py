import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.db.base import Base
from zeroshield.intelligence.repository import VulnerabilityRepository


@pytest.fixture
def vuln_repo() -> VulnerabilityRepository:
    """In-memory SQLite-backed VulnerabilityRepository - StaticPool + a single
    shared connection so the same in-memory database is visible across
    threads/sessions (a plain sqlite:///:memory: engine gives every new
    connection its own separate, empty database)."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return VulnerabilityRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))
