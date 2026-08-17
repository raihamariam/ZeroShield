import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.repository import AuthRepository
from zeroshield.db.base import Base


@pytest.fixture
def session_factory():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def auth_repo(session_factory) -> AuthRepository:
    return AuthRepository(session_factory)


@pytest.fixture
def audit_repo(session_factory) -> AuditRepository:
    return AuditRepository(session_factory)
