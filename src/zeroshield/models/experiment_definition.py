import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from zeroshield.models._shared import (
    EXPERIMENT_ID_PATTERN,
    ExperimentId,
    StrategyId,
    is_unsafe_relative_path,
)
from zeroshield.models.cve_reference import CVEReference
from zeroshield.models.enums import (
    ApprovalStatus,
    Domain,
    InputClassification,
    MetricName,
    RootCauseCategory,
    SafetyLevel,
)

_EXPERIMENT_ID_RE = re.compile(EXPERIMENT_ID_PATTERN)


class ExperimentDefinition(BaseModel):
    """Experiment definition, per SRS FR-001/FR-002/FR-003/FR-004 and §6.3 schema."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: ExperimentId = Field(frozen=True)
    title: str = Field(min_length=1)
    domain: Domain
    description: str = Field(min_length=1)
    related_cves: list[CVEReference] = Field(min_length=1)
    failure_pattern: str = Field(min_length=1)
    root_cause: RootCauseCategory
    vendor_mitigation: str = Field(min_length=1)
    mitigation_gap: str = Field(min_length=1)
    research_question: str = Field(min_length=1)
    hypothesis: str = Field(min_length=1)
    safety_level: SafetyLevel
    external_targeting: bool = False
    input_classification: InputClassification = InputClassification.SYNTHETIC
    weaponised_payloads: bool = False
    baseline_strategy: StrategyId
    mitigation_strategy: StrategyId
    dataset_path: Path
    metrics_to_collect: list[MetricName] = Field(min_length=1)
    approval_status: ApprovalStatus = ApprovalStatus.DRAFT
    version: str = Field(default="1.0.0", min_length=1)

    @field_validator("dataset_path")
    @classmethod
    def dataset_path_must_be_relative(cls, v: Path) -> Path:
        if is_unsafe_relative_path(v):
            raise ValueError(
                "dataset_path must be a relative path with no '..' segments, for portability "
                "and reproducibility"
            )
        return v

    @model_validator(mode="after")
    def check_domain_matches_experiment_id(self) -> "ExperimentDefinition":
        match = _EXPERIMENT_ID_RE.match(self.experiment_id)
        if not match or match.group(1) != self.domain.value:
            raise ValueError(
                f"experiment_id '{self.experiment_id}' domain segment does not match "
                f"domain field '{self.domain.value}'"
            )
        return self

    @model_validator(mode="after")
    def check_related_cves_match_domain(self) -> "ExperimentDefinition":
        mismatched = [c.cve_id for c in self.related_cves if c.domain != self.domain]
        if mismatched:
            raise ValueError(
                f"related_cves contains CVEs outside the experiment's domain "
                f"({self.domain.value}): {mismatched}"
            )
        return self

    @model_validator(mode="after")
    def check_baseline_and_mitigation_differ(self) -> "ExperimentDefinition":
        if self.baseline_strategy == self.mitigation_strategy:
            raise ValueError(
                "baseline_strategy and mitigation_strategy must be different strategy identifiers"
            )
        return self

    @model_validator(mode="after")
    def check_metrics_to_collect_unique(self) -> "ExperimentDefinition":
        if len(set(self.metrics_to_collect)) != len(self.metrics_to_collect):
            raise ValueError("metrics_to_collect must not contain duplicate entries")
        return self
