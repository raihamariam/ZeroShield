"""End-to-end Telecom validation against SRS Phase 1 acceptance criteria (Milestone 15).

Each test is labeled with the AC/QG it checks. AC-01 (approval), AC-02 (GitHub/Overleaf
links), and AC-10 (Project Lead review) are NOT fully checkable by code and are reported,
not silently claimed - see the accompanying milestone summary.
"""

import json
from pathlib import Path

import pytest

from zeroshield.models import ApprovalStatus, Decision, ExperimentDefinition, TestCaseCategory
from zeroshield.orchestration import execute_and_generate_evidence
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import LocalEvidenceRepository, verify_manifest_integrity
from zeroshield.runners import ExperimentRunner, PolicyRefusalError
from zeroshield.strategies.telecom import (
    StrictGrammarStateMachineMitigation,
    WeakMandatoryFieldStateBaseline,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT_PATH = REPO_ROOT / "experiments" / "ZC-TELECOM-EXP-001.json"
DATASET_PATH = REPO_ROOT / "test_data" / "telecom" / "telecom_sip_session_setup_dataset.json"


def _load_telecom_experiment() -> ExperimentDefinition:
    data = json.loads(EXPERIMENT_PATH.read_text(encoding="utf-8"))
    return ExperimentDefinition(**data)


@pytest.fixture
def telecom_validation(tmp_path: Path):
    experiment = _load_telecom_experiment()
    repo = LocalEvidenceRepository(tmp_path)
    result = execute_and_generate_evidence(
        experiment,
        DATASET_PATH,
        baseline=WeakMandatoryFieldStateBaseline(),
        mitigation=StrictGrammarStateMachineMitigation(),
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="0123456",
        evidence_repository=repo,
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )
    return experiment, repo, result


def test_ac01_exactly_one_telecom_experiment_definition_exists() -> None:
    telecom_experiments = list((REPO_ROOT / "experiments").glob("ZC-TELECOM-EXP-*.json"))
    assert len(telecom_experiments) == 1
    # NOTE: AC-01 requires the experiment be *approved*. ZC-TELECOM-EXP-001 is still draft
    # pending D-02 (Project Lead sign-off on the anchor CVE pattern) - not yet satisfied.


def test_ac01_both_vpn_and_telecom_experiment_definitions_are_delivered() -> None:
    vpn_experiments = list((REPO_ROOT / "experiments").glob("ZC-VPN-EXP-*.json"))
    telecom_experiments = list((REPO_ROOT / "experiments").glob("ZC-TELECOM-EXP-*.json"))
    assert len(vpn_experiments) == 1
    assert len(telecom_experiments) == 1
    # NOTE: both experiment *definitions* now exist (Phase 1 technical delivery), but AC-01's
    # "approved" requirement is not satisfied for either - D-01 and D-02 both remain open.


def test_ac02_experiment_links_to_cve_evidence_and_test_set(telecom_validation) -> None:
    experiment, _repo, _result = telecom_validation
    assert len(experiment.related_cves) >= 1
    assert all(cve.source_urls for cve in experiment.related_cves)
    assert DATASET_PATH.is_file()
    # NOTE: "GitHub task" and "Overleaf section" links are process artifacts outside
    # this codebase and are not verifiable here.


def test_ac03_all_valid_cases_accepted_in_both_modes(telecom_validation) -> None:
    _experiment, _repo, result = telecom_validation
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    valid_ids = {c["case_id"] for c in dataset["cases"] if c["category"] == TestCaseCategory.VALID.value}

    baseline_valid = [r for r in result.execution.baseline.case_results if r.case_id in valid_ids]
    mitigation_valid = [r for r in result.execution.mitigation.case_results if r.case_id in valid_ids]
    assert len(baseline_valid) == len(valid_ids)
    assert len(mitigation_valid) == len(valid_ids)
    assert all(r.decision == Decision.ACCEPTED for r in baseline_valid)
    assert all(r.decision == Decision.ACCEPTED for r in mitigation_valid)


def test_ac04_mitigation_blocks_malformed_conditions_before_processing(telecom_validation) -> None:
    _experiment, _repo, result = telecom_validation
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    malformed_ids = {
        c["case_id"] for c in dataset["cases"] if c["category"] == TestCaseCategory.MALFORMED.value
    }
    mitigation_malformed = [
        r for r in result.execution.mitigation.case_results if r.case_id in malformed_ids
    ]
    assert len(mitigation_malformed) == len(malformed_ids)
    assert all(r.decision == Decision.BLOCKED for r in mitigation_malformed)
    assert all(not r.parser_reached for r in mitigation_malformed)


def test_ac05_baseline_and_mitigation_use_identical_dataset(telecom_validation) -> None:
    _experiment, _repo, result = telecom_validation
    assert result.execution.baseline.run.dataset_hash == result.execution.mitigation.run.dataset_hash
    baseline_case_ids = [r.case_id for r in result.execution.baseline.case_results]
    mitigation_case_ids = [r.case_id for r in result.execution.mitigation.case_results]
    assert baseline_case_ids == mitigation_case_ids


def test_ac06_every_mitigation_rejection_is_logged(telecom_validation) -> None:
    _experiment, _repo, result = telecom_validation
    blocked = [r for r in result.execution.mitigation.case_results if r.decision == Decision.BLOCKED]
    assert len(blocked) > 0
    assert all(r.logged for r in blocked)


def test_ac07_comparison_includes_effectiveness_fp_fn_parser_reach_latency(telecom_validation) -> None:
    _experiment, _repo, result = telecom_validation
    report = result.comparison_report
    assert -1.0 <= report.block_rate_improvement <= 1.0
    for metrics in (report.baseline_metrics, report.mitigation_metrics):
        assert 0.0 <= metrics.false_positive_rate <= 1.0
        assert 0.0 <= metrics.false_negative_rate <= 1.0
        assert 0.0 <= metrics.parser_reach_rate <= 1.0
        assert metrics.mean_latency_ms >= 0.0
    assert isinstance(report.latency_overhead_ms, float)
    assert len(report.limitations) >= 1


def test_ac08_both_evidence_manifests_pass_integrity_verification(telecom_validation) -> None:
    _experiment, repo, result = telecom_validation
    baseline_manifest = repo.load_manifest("ZC-TELECOM-EXP-001", result.execution.baseline.run.run_id)
    mitigation_manifest = repo.load_manifest(
        "ZC-TELECOM-EXP-001", result.execution.mitigation.run.run_id
    )
    assert verify_manifest_integrity(baseline_manifest) is True
    assert verify_manifest_integrity(mitigation_manifest) is True


def test_ac09_no_unsafe_execution_configuration(telecom_validation) -> None:
    experiment, _repo, _result = telecom_validation
    assert experiment.external_targeting is False
    assert experiment.weaponised_payloads is False
    assert experiment.safety_level.value == "SYNTHETIC_ONLY"

    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    suspicious_keys = {"password", "passwd", "secret", "api_key", "apikey", "token", "private_key"}
    for case in dataset["cases"]:
        keys_lower = {str(k).lower() for k in case["input_data"]}
        assert not keys_lower & suspicious_keys


def test_ac09_unapproved_experiment_still_refused_for_real_execution() -> None:
    experiment = _load_telecom_experiment()
    assert experiment.approval_status == ApprovalStatus.DRAFT
    with pytest.raises(PolicyRefusalError):
        ExperimentRunner().run(
            experiment,
            DATASET_PATH,
            baseline=WeakMandatoryFieldStateBaseline(),
            mitigation=StrictGrammarStateMachineMitigation(),
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="0123456",
            execution_context=ExecutionContext.EXPERIMENT_RUN,
        )


def test_qg3_baseline_demonstrates_expected_weakness_safely(telecom_validation) -> None:
    _experiment, _repo, result = telecom_validation
    assert result.comparison_report.baseline_metrics.block_rate == 0.0
    assert not any(r.errored for r in result.execution.baseline.case_results)


def test_qg4_mitigation_passes_with_valid_traffic_preserved(telecom_validation) -> None:
    _experiment, _repo, result = telecom_validation
    assert result.comparison_report.mitigation_metrics.valid_acceptance_rate == 1.0
    assert not any(r.errored for r in result.execution.mitigation.case_results)


def test_qg5_manifest_raw_results_and_comparison_all_verified(telecom_validation) -> None:
    _experiment, repo, result = telecom_validation
    assert result.baseline_manifest_path.is_file()
    assert result.mitigation_manifest_path.is_file()
    assert result.comparison_path.is_file()
    baseline_manifest = repo.load_manifest("ZC-TELECOM-EXP-001", result.execution.baseline.run.run_id)
    assert verify_manifest_integrity(baseline_manifest) is True
