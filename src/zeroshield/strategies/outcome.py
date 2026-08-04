from pydantic import BaseModel, ConfigDict, model_validator

from zeroshield.models.enums import Decision


class StrategyOutcome(BaseModel):
    """What a ProcessingStrategy determines for one input, per FR-007 (decision/parser-reach)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Decision
    parser_reached: bool
    logged: bool = False  # a decision that this case merits a security event, not proof one was emitted
    errored: bool = False
    error_message: str | None = None

    @model_validator(mode="after")
    def check_error_message_consistency(self) -> "StrategyOutcome":
        if self.errored and not self.error_message:
            raise ValueError("error_message is required when errored is True")
        if not self.errored and self.error_message is not None:
            raise ValueError("error_message must be None when errored is False")
        return self
