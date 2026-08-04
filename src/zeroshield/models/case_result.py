from pydantic import BaseModel, ConfigDict, Field, model_validator

from zeroshield.models._shared import RunId
from zeroshield.models.enums import Decision


class CaseResult(BaseModel):
    """Per-case outcome record, per SRS FR-007 and §7.1 (Result entity, append-only per §7.2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: RunId
    case_id: str = Field(min_length=1)
    decision: Decision
    parser_reached: bool
    errored: bool
    error_message: str | None = None
    logged: bool
    latency_ms: float = Field(ge=0.0)

    @model_validator(mode="after")
    def check_error_message_consistency(self) -> "CaseResult":
        if self.errored and not self.error_message:
            raise ValueError("error_message is required when errored is True")
        if not self.errored and self.error_message is not None:
            raise ValueError("error_message must be None when errored is False")
        return self
