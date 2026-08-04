from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from zeroshield.models._shared import SafetyRuleId


class PolicyDecision(BaseModel):
    """Shape of a safety-policy evaluation outcome, per SRS FR-011 and §10.1 (SAFE-* rules)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool
    evaluated_at: datetime
    rule_results: dict[SafetyRuleId, bool] = Field(min_length=1)
    reasons: list[str] = Field(default_factory=list)
    policy_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def check_reasons_present_when_denied(self) -> "PolicyDecision":
        if not self.allowed and not self.reasons:
            raise ValueError("reasons must be provided when allowed is False")
        return self

    @model_validator(mode="after")
    def check_allowed_consistent_with_rule_results(self) -> "PolicyDecision":
        all_passed = all(self.rule_results.values())
        if not self.allowed and all_passed:
            raise ValueError("allowed=False requires at least one failed rule_results entry")
        if self.allowed and not all_passed:
            raise ValueError("allowed=True requires all rule_results entries to pass")
        return self
