from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from zeroshield.models._shared import ExperimentId, RunId
from zeroshield.models.experiment_metrics import ExperimentMetrics


class ComparisonReport(BaseModel):
    """Baseline-vs-mitigated comparison, per FR-009 (counts/rates/overhead/limitations) and AC-07."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    experiment_id: ExperimentId
    baseline_run_id: RunId
    mitigation_run_id: RunId
    total_cases: int = Field(ge=1)
    baseline_metrics: ExperimentMetrics
    mitigation_metrics: ExperimentMetrics
    block_rate_improvement: float = Field(ge=-1.0, le=1.0)
    latency_overhead_ms: float
    limitations: list[str] = Field(min_length=1)
    generated_at: datetime

    @model_validator(mode="after")
    def check_run_ids_differ(self) -> "ComparisonReport":
        if self.baseline_run_id == self.mitigation_run_id:
            raise ValueError("baseline_run_id and mitigation_run_id must be different runs")
        return self

    @model_validator(mode="after")
    def check_metrics_run_ids_match(self) -> "ComparisonReport":
        if self.baseline_metrics.run_id != self.baseline_run_id:
            raise ValueError("baseline_metrics.run_id must match baseline_run_id")
        if self.mitigation_metrics.run_id != self.mitigation_run_id:
            raise ValueError("mitigation_metrics.run_id must match mitigation_run_id")
        return self
