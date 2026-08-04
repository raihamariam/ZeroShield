from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from zeroshield.models._shared import Rate, RunId


class ExperimentMetrics(BaseModel):
    """Aggregate computed metrics for a run, per SRS FR-008 and §7.1 (Metric entity)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: RunId
    processing_success_rate: Rate
    block_rate: Rate
    valid_acceptance_rate: Rate
    false_positive_rate: Rate
    false_negative_rate: Rate
    parser_reach_rate: Rate
    mean_latency_ms: float = Field(ge=0.0)
    log_completeness_rate: Rate
    calculated_at: datetime
    calculation_version: str = Field(min_length=1)
