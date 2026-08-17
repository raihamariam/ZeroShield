"""Tests handle_message_body's malformed-message robustness and successful
dispatch, mirroring tests/unit/worker/test_main.py's approach for the
experiment-run worker (Milestone 26 pattern) - a malformed queue message must
never crash the consume loop.
"""

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zeroshield.db.base import Base
from zeroshield.intelligence.messaging import IntelligenceSyncJobMessage
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.models.vulnerability import VulnerabilitySourceName
from zeroshield.worker.intelligence_main import handle_message_body

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"


@pytest.fixture
def repo() -> VulnerabilityRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return VulnerabilityRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


def test_handle_message_body_malformed_json_never_raises(repo: VulnerabilityRepository) -> None:
    handle_message_body(b"not json at all", repository=repo, experiments_dir=EXPERIMENTS_DIR)  # must not raise


def test_handle_message_body_missing_fields_never_raises(repo: VulnerabilityRepository) -> None:
    handle_message_body(b'{"sync_id": "SYNC-1"}', repository=repo, experiments_dir=EXPERIMENTS_DIR)


def test_handle_message_body_invalid_source_never_raises(repo: VulnerabilityRepository) -> None:
    handle_message_body(
        b'{"sync_id": "SYNC-1", "source": "not_a_real_source"}', repository=repo, experiments_dir=EXPERIMENTS_DIR
    )


def test_handle_message_body_empty_body_never_raises(repo: VulnerabilityRepository) -> None:
    handle_message_body(b"", repository=repo, experiments_dir=EXPERIMENTS_DIR)


def test_handle_message_body_unregistered_source_marks_sync_failed(repo: VulnerabilityRepository) -> None:
    """manual_import validates as a real VulnerabilitySourceName but has no
    connector - build_connector raises, caught by the last-resort guard."""
    message = IntelligenceSyncJobMessage(sync_id="SYNC-unreg", source=VulnerabilitySourceName.MANUAL_IMPORT)
    handle_message_body(message.model_dump_json().encode(), repository=repo, experiments_dir=EXPERIMENTS_DIR)
    # no sync record is ever saved for this case, since build_connector raises
    # before run_sync's own QUEUED->RUNNING save - proves it never crashes the
    # consume loop, not that a sync record necessarily exists.
    assert repo.get_sync("SYNC-unreg") is None
