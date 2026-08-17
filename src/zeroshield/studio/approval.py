"""Explicit approval state machine (V2 Phase 3, Step 5).

Approval never bypasses SafetyPolicy: transitioning a version to APPROVED
only changes zeroshield.models.ExperimentVersion.status and, in lockstep,
definition.approval_status - it never touches, calls, or overrides
SafetyPolicy in any way. Execution remains: APPROVED (workflow state) ->
SafetyPolicy.evaluate() (still the real, independent gate, unchanged since
Phase 1) -> sandbox -> run. See zeroshield.studio.builder for where an
APPROVED version is materialised into a runnable ExperimentDefinition file.

`actor` is a plain string today (no auth system exists until Phase 6) -
every ApprovalDecision already records who/when/why, so the audit trail is
RBAC-ready without changes once Phase 6 adds real identities.
"""

from collections.abc import Callable
from datetime import UTC, datetime

from zeroshield.models.enums import ApprovalStatus, ExperimentVersionStatus
from zeroshield.models.experiment_version import ApprovalDecision, ExperimentVersion

_ALLOWED_TRANSITIONS: dict[ExperimentVersionStatus, frozenset[ExperimentVersionStatus]] = {
    ExperimentVersionStatus.DRAFT: frozenset({ExperimentVersionStatus.READY_FOR_REVIEW}),
    ExperimentVersionStatus.READY_FOR_REVIEW: frozenset(
        {ExperimentVersionStatus.UNDER_REVIEW, ExperimentVersionStatus.DRAFT}
    ),
    ExperimentVersionStatus.UNDER_REVIEW: frozenset(
        {
            ExperimentVersionStatus.APPROVED,
            ExperimentVersionStatus.REJECTED,
            ExperimentVersionStatus.READY_FOR_REVIEW,
        }
    ),
    ExperimentVersionStatus.APPROVED: frozenset({ExperimentVersionStatus.RETIRED}),
    ExperimentVersionStatus.REJECTED: frozenset(),
    ExperimentVersionStatus.RETIRED: frozenset(),
}


class InvalidTransitionError(Exception):
    def __init__(self, current: ExperimentVersionStatus, target: ExperimentVersionStatus) -> None:
        allowed = sorted(s.value for s in _ALLOWED_TRANSITIONS.get(current, frozenset()))
        super().__init__(
            f"cannot transition from '{current.value}' to '{target.value}'; allowed targets from "
            f"'{current.value}': {allowed}"
        )
        self.current = current
        self.target = target


def check_transition(current: ExperimentVersionStatus, target: ExperimentVersionStatus) -> None:
    if target not in _ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise InvalidTransitionError(current, target)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def transition(
    version: ExperimentVersion,
    target: ExperimentVersionStatus,
    *,
    actor: str,
    reason: str | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> tuple[ExperimentVersion, ApprovalDecision]:
    """Applies an explicit, allow-listed status transition. Never re-runs
    SafetyPolicy (that is ExperimentRunner.run()'s job, at actual run time,
    every time, regardless of approval history) - this function only updates
    workflow bookkeeping and keeps definition.approval_status in lockstep."""
    check_transition(version.status, target)
    now = clock()

    new_definition_status = ApprovalStatus.APPROVED if target is ExperimentVersionStatus.APPROVED else ApprovalStatus.DRAFT
    new_definition = version.definition.model_copy(update={"approval_status": new_definition_status})
    new_version = version.model_copy(update={"status": target, "definition": new_definition, "updated_at": now})

    decision = ApprovalDecision(
        version_id=version.version_id,
        from_status=version.status,
        to_status=target,
        actor=actor,
        reason=reason,
        decided_at=now,
    )
    return new_version, decision
