from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from zeroshield.models import ExperimentRun, RunStatus


def _base_run_data() -> dict:
    return {
        "run_id": "RUN-001",
        "experiment_id": "ZC-VPN-EXP-999",
        "mode": "baseline",
        "dataset_hash": "a" * 64,
        "git_commit": "abc1234",
        "environment": {"python_version": "3.12.10"},
        "started_at": datetime(2026, 7, 13, 12, 0, 0, tzinfo=UTC),
    }


def test_valid_pending_run_parses() -> None:
    run = ExperimentRun(**_base_run_data())
    assert run.status == RunStatus.PENDING
    assert run.completed_at is None


def test_valid_completed_run_parses() -> None:
    data = _base_run_data()
    data["status"] = "completed"
    data["completed_at"] = data["started_at"] + timedelta(seconds=5)
    run = ExperimentRun(**data)
    assert run.status == RunStatus.COMPLETED


def test_completed_before_started_rejected() -> None:
    data = _base_run_data()
    data["status"] = "completed"
    data["completed_at"] = data["started_at"] - timedelta(seconds=5)
    with pytest.raises(ValidationError, match="cannot be earlier"):
        ExperimentRun(**data)


def test_completed_status_requires_completed_at() -> None:
    data = _base_run_data()
    data["status"] = "completed"
    with pytest.raises(ValidationError, match="requires completed_at"):
        ExperimentRun(**data)


def test_pending_status_forbids_completed_at() -> None:
    data = _base_run_data()
    data["completed_at"] = data["started_at"] + timedelta(seconds=5)
    with pytest.raises(ValidationError, match="must not have completed_at"):
        ExperimentRun(**data)


def test_invalid_dataset_hash_rejected() -> None:
    data = _base_run_data()
    data["dataset_hash"] = "not-a-hash"
    with pytest.raises(ValidationError, match="dataset_hash"):
        ExperimentRun(**data)


def test_invalid_git_commit_rejected() -> None:
    data = _base_run_data()
    data["git_commit"] = "xyz"
    with pytest.raises(ValidationError, match="git_commit"):
        ExperimentRun(**data)
