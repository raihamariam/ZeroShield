"""Control effectiveness aggregation (V2 Phase 5, Step 9).

"Aggregate repeated comparable validations... do not average incompatible
experiments blindly." Comparability here is scoped to a single
ControlVersion (same domain, same mitigation strategy, same experiment
definition version - see zeroshield.assurance.models.ControlVersion): only
validations sharing a version_id are ever averaged together. Trend across
versions is reported as a list, not blended into one number, so a version
bump is always visible as a step in the trend rather than silently smoothed
into an average that spans two different things being measured.
"""

from dataclasses import dataclass, field
from datetime import datetime

from zeroshield.assurance.models import ControlValidation


@dataclass(frozen=True)
class ControlEffectivenessSummary:
    control_id: str
    current_version_id: str | None
    current_version_label: str | None
    validation_count_current_version: int
    total_validation_count: int
    mean_block_rate_improvement_current_version: float | None
    latest_verdict: str | None
    previous_verdict: str | None
    last_validated_at: datetime | None
    trend: list[ControlValidation] = field(default_factory=list)
    comparability_note: str = (
        "Aggregate metrics are computed only across validations of the same control version - "
        "results are never averaged across versions with a different domain, strategy, or "
        "experiment-definition version."
    )


def summarise_effectiveness(control_id: str, validations: list[ControlValidation]) -> ControlEffectivenessSummary | None:
    """`validations` must be oldest -> newest (zeroshield.assurance.
    repository.list_validations' natural order) and already scoped to one
    control. Returns None if there is no validation history at all."""
    if not validations:
        return None

    latest = validations[-1]
    previous = validations[-2] if len(validations) >= 2 else None

    current_version_validations = [v for v in validations if v.version_id == latest.version_id]
    mean_block_rate = sum(v.block_rate_improvement for v in current_version_validations) / len(
        current_version_validations
    )

    return ControlEffectivenessSummary(
        control_id=control_id,
        current_version_id=latest.version_id,
        current_version_label=latest.version_id,
        validation_count_current_version=len(current_version_validations),
        total_validation_count=len(validations),
        mean_block_rate_improvement_current_version=round(mean_block_rate, 4),
        latest_verdict=latest.verdict_label,
        previous_verdict=previous.verdict_label if previous is not None else None,
        last_validated_at=latest.validated_at,
        trend=validations,
    )
