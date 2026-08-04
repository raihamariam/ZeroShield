from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from zeroshield.models._shared import (
    ExperimentId,
    GitCommitHex,
    RunId,
    Sha256Hex,
    StrategyId,
    is_unsafe_relative_path,
)
from zeroshield.models.enums import ApprovalStatus, RunMode
from zeroshield.models.experiment_metrics import ExperimentMetrics
from zeroshield.models.policy_decision import PolicyDecision


class EvidenceManifest(BaseModel):
    """Per-run evidence manifest, per SRS FR-010 and §15.2 (Evidence Manifest Example)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_version: str = Field(min_length=1)
    experiment_id: ExperimentId
    experiment_version: str = Field(min_length=1)
    run_id: RunId
    mode: RunMode
    test_set_id: str = Field(min_length=1)
    test_set_sha256: Sha256Hex
    git_commit: GitCommitHex
    container_image_digest: str | None = None
    started_at: datetime
    completed_at: datetime
    strategy_id: StrategyId
    metrics: ExperimentMetrics
    artefact_paths: dict[str, Path] = Field(min_length=1)
    safety_decision: PolicyDecision
    review_status: ApprovalStatus
    manifest_sha256: Sha256Hex

    @field_validator("artefact_paths")
    @classmethod
    def artefact_paths_must_be_relative(cls, v: dict[str, Path]) -> dict[str, Path]:
        unsafe = [name for name, p in v.items() if is_unsafe_relative_path(p)]
        if unsafe:
            raise ValueError(
                f"artefact_paths must be relative paths with no '..' segments, found unsafe "
                f"for: {unsafe}"
            )
        return v

    @model_validator(mode="after")
    def check_completed_after_started(self) -> "EvidenceManifest":
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot be earlier than started_at")
        return self

    @model_validator(mode="after")
    def check_metrics_run_id_matches(self) -> "EvidenceManifest":
        if self.metrics.run_id != self.run_id:
            raise ValueError("metrics.run_id must match the manifest's run_id")
        return self
