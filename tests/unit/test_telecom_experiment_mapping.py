import json
from pathlib import Path

from zeroshield.models import (
    ApprovalStatus,
    Domain,
    ExperimentDefinition,
    InputClassification,
    RootCauseCategory,
)
from zeroshield.policies import ExecutionContext, SafetyPolicy

EXPERIMENTS_DIR = Path(__file__).resolve().parents[2] / "experiments"


def _load_telecom_experiment() -> ExperimentDefinition:
    data = json.loads((EXPERIMENTS_DIR / "ZC-TELECOM-EXP-001.json").read_text(encoding="utf-8"))
    return ExperimentDefinition(**data)


def test_telecom_experiment_definition_parses() -> None:
    experiment = _load_telecom_experiment()
    assert experiment.experiment_id == "ZC-TELECOM-EXP-001"
    assert experiment.domain == Domain.TELECOM
    assert experiment.safety_level.value == "SYNTHETIC_ONLY"
    assert experiment.root_cause == RootCauseCategory.PARSER_MESSAGE_HANDLING_FAILURE


def test_telecom_experiment_cites_four_related_samsung_sdp_cves() -> None:
    experiment = _load_telecom_experiment()
    assert len(experiment.related_cves) == 4
    cited_ids = {c.cve_id for c in experiment.related_cves}
    assert cited_ids == {
        "CVE-2023-24033",
        "CVE-2023-26496",
        "CVE-2023-26497",
        "CVE-2023-26498",
    }
    assert all(c.domain == Domain.TELECOM for c in experiment.related_cves)
    assert all(c.source_urls for c in experiment.related_cves)


def test_telecom_experiment_is_still_draft_pending_approval() -> None:
    experiment = _load_telecom_experiment()
    assert experiment.approval_status == ApprovalStatus.DRAFT


def test_telecom_experiment_declares_synthetic_only_safety_posture() -> None:
    experiment = _load_telecom_experiment()
    assert experiment.external_targeting is False
    assert experiment.weaponised_payloads is False
    assert experiment.input_classification == InputClassification.SYNTHETIC


def test_telecom_experiment_denied_for_real_run_until_approved() -> None:
    experiment = _load_telecom_experiment()
    policy = SafetyPolicy()
    decision = policy.evaluate(experiment, execution_context=ExecutionContext.EXPERIMENT_RUN)
    assert decision.allowed is False
    assert decision.rule_results["SAFE-004"] is False


def test_telecom_experiment_passes_safety_checks_for_local_unit_test() -> None:
    experiment = _load_telecom_experiment()
    policy = SafetyPolicy()
    decision = policy.evaluate(experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST)
    assert decision.allowed is True
    assert all(decision.rule_results.values())


def test_exactly_one_telecom_experiment_definition_exists() -> None:
    telecom_experiments = list(EXPERIMENTS_DIR.glob("ZC-TELECOM-EXP-*.json"))
    assert len(telecom_experiments) == 1
