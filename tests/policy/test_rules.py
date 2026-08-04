from zeroshield.models import ApprovalStatus, ExperimentDefinition
from zeroshield.policies import ExecutionContext
from zeroshield.policies.rules import (
    check_safe_001_external_targeting,
    check_safe_002_input_classification,
    check_safe_003_weaponised_payloads,
    check_safe_004_approval_status,
)


def test_safe_001_passes_when_external_targeting_false(
    valid_experiment_definition_data: dict,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_001_external_targeting(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is True
    assert reason is None


def test_safe_001_fails_when_external_targeting_true(
    valid_experiment_definition_data: dict,
) -> None:
    valid_experiment_definition_data["external_targeting"] = True
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_001_external_targeting(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is False
    assert reason is not None and "SAFE-001" in reason


def test_safe_002_passes_when_input_classification_synthetic(
    valid_experiment_definition_data: dict,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_002_input_classification(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is True
    assert reason is None


def test_safe_002_fails_when_input_classification_not_synthetic(
    valid_experiment_definition_data: dict,
) -> None:
    valid_experiment_definition_data["input_classification"] = "benign"
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_002_input_classification(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is False
    assert reason is not None and "SAFE-002" in reason


def test_safe_003_passes_when_weaponised_payloads_false(
    valid_experiment_definition_data: dict,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_003_weaponised_payloads(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is True
    assert reason is None


def test_safe_003_fails_when_weaponised_payloads_true(
    valid_experiment_definition_data: dict,
) -> None:
    valid_experiment_definition_data["weaponised_payloads"] = True
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_003_weaponised_payloads(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is False
    assert reason is not None and "SAFE-003" in reason


def test_safe_004_passes_in_local_unit_test_context_regardless_of_approval(
    valid_experiment_definition_data: dict,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    assert experiment.approval_status == ApprovalStatus.DRAFT
    passed, reason = check_safe_004_approval_status(experiment, ExecutionContext.LOCAL_UNIT_TEST)
    assert passed is True
    assert reason is None


def test_safe_004_fails_for_experiment_run_when_not_approved(
    valid_experiment_definition_data: dict,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_004_approval_status(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is False
    assert reason is not None and "SAFE-004" in reason


def test_safe_004_passes_for_experiment_run_when_approved(
    valid_experiment_definition_data: dict,
) -> None:
    valid_experiment_definition_data["approval_status"] = ApprovalStatus.APPROVED.value
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    passed, reason = check_safe_004_approval_status(experiment, ExecutionContext.EXPERIMENT_RUN)
    assert passed is True
    assert reason is None
