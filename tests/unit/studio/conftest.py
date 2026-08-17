from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.db.base import Base
from zeroshield.studio.repository import ExperimentVersionRepository


@pytest.fixture(autouse=True)
def _cwd_is_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ExperimentDefinition.dataset_path must be relative to CWD (an existing,
    unmodified V1 validation rule - see models/experiment_definition.py) -
    every studio test therefore runs with CWD chdir'd into tmp_path, so the
    builder's default relative dataset_root/experiments_dir ("test_data/
    generated", "experiments") resolve exactly the way they do in production
    (Path.cwd()-relative), never needing an absolute-path override."""
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def version_repo() -> ExperimentVersionRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return ExperimentVersionRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))
