from zeroshield.models import ApprovalStatus, ExperimentDefinition, InputClassification, SafetyLevel
from zeroshield.policies.execution_context import ExecutionContext


def check_safe_001_external_targeting(
    experiment: ExperimentDefinition, execution_context: ExecutionContext
) -> tuple[bool, str | None]:
    if experiment.external_targeting:
        return False, (
            "SAFE-001: external_targeting must be false; no documented-authorisation "
            "mechanism exists in Phase 1."
        )
    return True, None


def check_safe_002_input_classification(
    experiment: ExperimentDefinition, execution_context: ExecutionContext
) -> tuple[bool, str | None]:
    if (
        experiment.safety_level == SafetyLevel.SYNTHETIC_ONLY
        and experiment.input_classification != InputClassification.SYNTHETIC
    ):
        return False, (
            "SAFE-002: safety_level 'SYNTHETIC_ONLY' requires input_classification "
            f"'synthetic', got '{experiment.input_classification.value}'."
        )
    return True, None


def check_safe_003_weaponised_payloads(
    experiment: ExperimentDefinition, execution_context: ExecutionContext
) -> tuple[bool, str | None]:
    if experiment.weaponised_payloads:
        return False, "SAFE-003: weaponised_payloads must be false for Phase 1."
    return True, None


def check_safe_004_approval_status(
    experiment: ExperimentDefinition, execution_context: ExecutionContext
) -> tuple[bool, str | None]:
    if execution_context is ExecutionContext.LOCAL_UNIT_TEST:
        return True, None
    if experiment.approval_status != ApprovalStatus.APPROVED:
        return False, (
            "SAFE-004: experiment must be approved before execution outside local unit "
            f"tests (current status: '{experiment.approval_status.value}')."
        )
    return True, None
