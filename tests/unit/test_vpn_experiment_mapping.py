import json
from pathlib import Path

from zeroshield.models import (
    ApprovalStatus,
    Domain,
    ExperimentDefinition,
    InputClassification,
    RootCauseCategory,
    SafetyLevel,
)
from zeroshield.policies import ExecutionContext, SafetyPolicy

EXPERIMENTS_DIR = Path(__file__).resolve().parents[2] / "experiments"


def _load_vpn_experiment() -> ExperimentDefinition:
    data = json.loads((EXPERIMENTS_DIR / "ZC-VPN-EXP-001.json").read_text(encoding="utf-8"))
    return ExperimentDefinition(**data)


def test_vpn_experiment_definition_parses() -> None:
    experiment = _load_vpn_experiment()
    assert experiment.experiment_id == "ZC-VPN-EXP-001"
    assert experiment.domain == Domain.VPN
    assert experiment.safety_level == SafetyLevel.SYNTHETIC_ONLY
    assert experiment.root_cause == RootCauseCategory.INPUT_VALIDATION_FAILURE


def test_vpn_experiment_cites_at_least_three_high_relevance_cves() -> None:
    experiment = _load_vpn_experiment()
    assert len(experiment.related_cves) == 3
    cited_ids = {c.cve_id for c in experiment.related_cves}
    assert cited_ids == {"CVE-2024-21762", "CVE-2023-3519", "CVE-2019-19781"}
    assert all(c.cisa_kev for c in experiment.related_cves)
    assert all(c.domain == Domain.VPN for c in experiment.related_cves)


def test_vpn_experiment_is_still_draft_pending_approval() -> None:
    experiment = _load_vpn_experiment()
    assert experiment.approval_status == ApprovalStatus.DRAFT


def test_vpn_experiment_declares_synthetic_only_safety_posture() -> None:
    experiment = _load_vpn_experiment()
    assert experiment.external_targeting is False
    assert experiment.weaponised_payloads is False
    assert experiment.input_classification == InputClassification.SYNTHETIC


def test_vpn_experiment_denied_for_real_run_until_approved() -> None:
    experiment = _load_vpn_experiment()
    policy = SafetyPolicy()
    decision = policy.evaluate(experiment, execution_context=ExecutionContext.EXPERIMENT_RUN)
    assert decision.allowed is False
    assert decision.rule_results["SAFE-004"] is False


def test_vpn_experiment_passes_safety_checks_for_local_unit_test() -> None:
    experiment = _load_vpn_experiment()
    policy = SafetyPolicy()
    decision = policy.evaluate(experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST)
    assert decision.allowed is True
    assert all(decision.rule_results.values())
