from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from zeroshield.models._shared import ExperimentId, GitCommitHex, RunId, Sha256Hex
from zeroshield.models.enums import RunMode, RunStatus

_TERMINAL_STATUSES = (RunStatus.COMPLETED, RunStatus.FAILED)
_OPEN_STATUSES = (RunStatus.PENDING, RunStatus.RUNNING)


class ExperimentRun(BaseModel):
    """A single baseline or mitigated execution, per SRS FR-006 and §7.1 (Run entity)."""

    model_config = ConfigDict(extra="forbid")

    run_id: RunId = Field(frozen=True)
    experiment_id: ExperimentId = Field(frozen=True)
    mode: RunMode = Field(frozen=True)
    dataset_hash: Sha256Hex = Field(frozen=True)
    git_commit: GitCommitHex = Field(frozen=True)
    environment: dict[str, str] = Field(min_length=1, frozen=True)
    started_at: datetime = Field(frozen=True)
    completed_at: datetime | None = None
    status: RunStatus = RunStatus.PENDING

    @model_validator(mode="after")
    def check_completed_at_after_started_at(self) -> "ExperimentRun":
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at cannot be earlier than started_at")
        return self

    @model_validator(mode="after")
    def check_status_consistency(self) -> "ExperimentRun":
        if self.status in _TERMINAL_STATUSES and self.completed_at is None:
            raise ValueError(f"status '{self.status.value}' requires completed_at to be set")
        if self.status in _OPEN_STATUSES and self.completed_at is not None:
            raise ValueError(f"status '{self.status.value}' must not have completed_at set")
        return self
