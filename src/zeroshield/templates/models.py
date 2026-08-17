"""Reusable, versioned validation templates (V2 Phase 3, Step 2). A template
is the reusable "shape" of an experiment: which strategies it's allowed to
pair as baseline/mitigation, what input fields it requires, and what metrics/
safety level apply - derived from real, already-working capabilities
(schema validation + canonicalisation for VPN, grammar/state-machine
enforcement for Telecom), not invented ones.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from zeroshield.models._shared import StrategyId
from zeroshield.models.enums import MetricName, SafetyLevel


class ValidationTemplate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    template_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    domain_pack_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    supported_failure_patterns: list[str] = Field(min_length=1)
    required_input_fields: list[str] = Field(min_length=1)
    allowed_baseline_strategies: list[StrategyId] = Field(min_length=1)
    allowed_mitigation_strategies: list[StrategyId] = Field(min_length=1)
    configurable_parameters: dict[str, Any] = Field(default_factory=dict)
    metrics_to_collect: list[MetricName] = Field(min_length=1)
    safety_level: SafetyLevel
