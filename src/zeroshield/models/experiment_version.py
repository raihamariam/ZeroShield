"""Experiment Studio's versioned draft/review wrapper (V2 Phase 3, Steps 4-5).

Deliberately embeds a real ExperimentDefinition (`definition`) rather than a
parallel, looser shape - "generated experiments must still map into the
trusted execution core" is satisfied structurally: there is no path from
Experiment Studio to a runnable experiment that does not pass through
ExperimentDefinition's own Pydantic validation.

`definition.approval_status` is kept in lockstep with `status` by
zeroshield.studio.approval's transition function, never set independently -
it can only become ApprovalStatus.APPROVED when `status` is
ExperimentVersionStatus.APPROVED, so SAFE-004 (SafetyPolicy's existing
approval check) is never bypassed by the Studio workflow; it is simply the
same trusted gate, fed a value the workflow can no longer forge.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from zeroshield.models._shared import ExperimentId
from zeroshield.models.enums import ApprovalStatus, ExperimentVersionStatus
from zeroshield.models.experiment_definition import ExperimentDefinition

_APPROVED_DEFINITION_STATUS = {ExperimentVersionStatus.APPROVED: ApprovalStatus.APPROVED}


class ExperimentVersion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version_id: str = Field(min_length=1)
    experiment_id: ExperimentId
    version_number: int = Field(ge=1)
    status: ExperimentVersionStatus
    domain_pack_id: str = Field(min_length=1)
    template_id: str = Field(min_length=1)
    template_version: str = Field(min_length=1)
    definition: ExperimentDefinition
    dataset_provenance: dict[str, object] | None = None
    created_by: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def check_experiment_id_matches_definition(self) -> "ExperimentVersion":
        if self.experiment_id != self.definition.experiment_id:
            raise ValueError("experiment_id must match definition.experiment_id")
        return self

    @model_validator(mode="after")
    def check_approval_status_matches_workflow_status(self) -> "ExperimentVersion":
        expected = _APPROVED_DEFINITION_STATUS.get(self.status, ApprovalStatus.DRAFT)
        if self.definition.approval_status != expected:
            raise ValueError(
                f"definition.approval_status must be '{expected.value}' when workflow status is "
                f"'{self.status.value}' - Experiment Studio approval must never desynchronise "
                "from the trusted core's own approval field"
            )
        return self


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version_id: str = Field(min_length=1)
    from_status: ExperimentVersionStatus
    to_status: ExperimentVersionStatus
    actor: str = Field(min_length=1)
    reason: str | None = None
    decided_at: datetime
