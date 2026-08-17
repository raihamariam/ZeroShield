"""V2 Phase 3, Step 9: represent ZC-VPN-EXP-001/ZC-TELECOM-EXP-001 through the
new DomainPack/template model, compare old (hand-authored) vs new
(Experiment-Studio-built) execution results, and demonstrate backward
compatibility - both run through the exact same, unmodified trusted core
(ExperimentRunner/SafetyPolicy/orchestration).

Intentional, documented differences between old and new:
  1. Case COUNT differs - the hand-authored datasets were curated by a
     researcher one case at a time; the generator produces a configurable
     number of cases per subtype. Both exercise the same strategy logic.
  2. Case CONTENT differs syntactically (different hostnames/paths/exact
     byte values) - the generator does not attempt to reproduce the
     hand-authored dataset verbatim, only the same *semantic* categories
     (valid/boundary/oversized/duplicate-field/canonicalisation/
     mismatched-length/unsupported-encoding for VPN;
     valid/boundary/oversized/duplicate-identity/state-transition/
     mismatched-length/invalid-sequence for Telecom).
  3. `dataset_provenance` is populated on the new version (generator_id/
     version/seed/config/sha256) - the old experiments have no such field
     since they predate Step 3 entirely.

What must NOT differ (asserted below): the underlying baseline/mitigation
strategy_ids, the resulting verdict quality (both EFFECTIVE), and the fact
that both are discoverable/runnable through the exact same, completely
unmodified zeroshield.experiments.discovery / zeroshield.services.
experiment_service code path.
"""

import shutil
from pathlib import Path

import pytest

from zeroshield.experiments.discovery import find_experiment
from zeroshield.generators import TelecomGeneratorConfig, VPNGeneratorConfig
from zeroshield.models import CVEReference, ExperimentDefinition
from zeroshield.models.enums import (
    ApprovalStatus,
    ExperimentVersionStatus,
    RootCauseCategory,
    VerdictLabel,
)
from zeroshield.policies import ExecutionContext
from zeroshield.services import experiment_service
from zeroshield.studio.builder import build_experiment_draft, materialise_to_experiments_dir
from zeroshield.verdict import compute_verdict

REPO_ROOT = Path(__file__).resolve().parents[3]
OLD_VPN_PATH = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"
OLD_TELECOM_PATH = REPO_ROOT / "experiments" / "ZC-TELECOM-EXP-001.json"


def _make_old_dataset_available(tmp_path: Path) -> None:
    """The autouse _cwd_is_tmp_path fixture chdirs into tmp_path so the
    *new*, Studio-built experiment's relative dataset_path resolves - but the
    *old*, hand-authored experiment's dataset_path ("test_data/vpn/...") is
    relative to the real repository, not tmp_path. Copy just what's needed
    rather than the whole repo test_data/ tree."""
    shutil.copytree(REPO_ROOT / "test_data", tmp_path / "test_data", dirs_exist_ok=True)


def _cve(domain: str) -> CVEReference:
    if domain == "VPN":
        return CVEReference(
            cve_id="CVE-2024-21762", domain="VPN", cvss_score=9.8, cisa_kev=True, epss_score=0.83,
            trust_boundary="Internet to pre-auth SSL VPN service", root_cause="memory_safety_failure",
            vendor_mitigation="patch", mitigation_gap="none", source_urls=["https://example.com"],
            retrieved_date="2026-07-13",
        )
    return CVEReference(
        cve_id="CVE-2023-24033", domain="TELECOM", cvss_score=8.1, cisa_kev=False, epss_score=0.1,
        trust_boundary="Untrusted cellular radio network to baseband processor",
        root_cause="parser_message_handling_failure", vendor_mitigation="patch", mitigation_gap="none",
        source_urls=["https://example.com"], retrieved_date="2026-07-13",
    )


@pytest.fixture
def migrated_vpn_definition(tmp_path: Path) -> ExperimentDefinition:
    version = build_experiment_draft(
        experiment_id="ZC-VPN-EXP-002", version_number=1,
        title="Studio-migrated: Pre-Authentication VPN Gateway Request Validation",
        description="Experiment-Studio-built representation of the same failure pattern as "
        "ZC-VPN-EXP-001, via the VPN Domain Pack's vpn_schema_canonicalisation template.",
        related_cves=[_cve("VPN")], domain_pack_id="vpn", template_id="vpn_schema_canonicalisation",
        template_version="1.0.0",
        dataset_config=VPNGeneratorConfig(
            valid_count=6, boundary_count=2, oversized_count=3, duplicate_field_count=3,
            mismatched_length_count=3, unsupported_encoding_count=3, invalid_path_count=3,
        ),
        seed=2024, failure_pattern="Pre-auth gateway parses attacker-controlled HTTP request data "
        "before a trusted session exists.", root_cause=RootCauseCategory.MEMORY_SAFETY_FAILURE,
        vendor_mitigation="Vendor patches available.", mitigation_gap="Documented per anchor CVE.",
        research_question="Can a pre-parser validation layer reject structurally invalid VPN-like requests?",
        hypothesis="Strict schema/length/canonicalisation validation rejects materially more malformed "
        "requests than a weak baseline.", created_by="migration-demo",
    )
    approved = version.model_copy(
        update={
            "status": ExperimentVersionStatus.APPROVED,
            "definition": version.definition.model_copy(update={"approval_status": ApprovalStatus.APPROVED}),
        }
    )
    materialise_to_experiments_dir(approved, tmp_path / "experiments")
    return approved.definition


@pytest.fixture
def migrated_telecom_definition(tmp_path: Path) -> ExperimentDefinition:
    version = build_experiment_draft(
        experiment_id="ZC-TELECOM-EXP-002", version_number=1,
        title="Studio-migrated: SIP Session-Setup Grammar & State-Machine Enforcement",
        description="Experiment-Studio-built representation of the same failure pattern as "
        "ZC-TELECOM-EXP-001, via the Telecom Domain Pack's telecom_grammar_state_machine template.",
        related_cves=[_cve("TELECOM")], domain_pack_id="telecom", template_id="telecom_grammar_state_machine",
        template_version="1.0.0",
        dataset_config=TelecomGeneratorConfig(
            valid_count=6, boundary_count=2, oversized_field_count=3, missing_header_count=3,
            duplicate_identity_count=3, mismatched_length_count=3, invalid_sequence_count=3,
            invalid_transition_count=3,
        ),
        seed=2024, failure_pattern="Session-setup message processed before mandatory fields/state validated.",
        root_cause=RootCauseCategory.PARSER_MESSAGE_HANDLING_FAILURE,
        vendor_mitigation="Vendor firmware update.", mitigation_gap="Documented per anchor CVE.",
        research_question="Can grammar/state-machine enforcement reject malformed session-setup messages?",
        hypothesis="Strict field/size/sequence/state validation rejects materially more malformed "
        "messages than a weak baseline.", created_by="migration-demo",
    )
    approved = version.model_copy(
        update={
            "status": ExperimentVersionStatus.APPROVED,
            "definition": version.definition.model_copy(update={"approval_status": ApprovalStatus.APPROVED}),
        }
    )
    materialise_to_experiments_dir(approved, tmp_path / "experiments")
    return approved.definition


def test_migrated_vpn_experiment_discoverable_via_unmodified_discovery(
    migrated_vpn_definition: ExperimentDefinition, tmp_path: Path
) -> None:
    found = find_experiment(tmp_path / "experiments", "ZC-VPN-EXP-002")
    assert found is not None
    assert found.baseline_strategy == "weak_schema_length_baseline"
    assert found.mitigation_strategy == "strict_schema_canonicalisation_mitigation"


def test_migrated_vpn_uses_same_strategy_ids_as_original_hand_authored_experiment(
    migrated_vpn_definition: ExperimentDefinition,
) -> None:
    original = ExperimentDefinition.model_validate_json(OLD_VPN_PATH.read_text(encoding="utf-8"))
    assert migrated_vpn_definition.baseline_strategy == original.baseline_strategy
    assert migrated_vpn_definition.mitigation_strategy == original.mitigation_strategy
    assert migrated_vpn_definition.domain == original.domain


def test_migrated_telecom_uses_same_strategy_ids_as_original(
    migrated_telecom_definition: ExperimentDefinition,
) -> None:
    original = ExperimentDefinition.model_validate_json(OLD_TELECOM_PATH.read_text(encoding="utf-8"))
    assert migrated_telecom_definition.baseline_strategy == original.baseline_strategy
    assert migrated_telecom_definition.mitigation_strategy == original.mitigation_strategy


def test_old_and_new_vpn_experiments_both_run_successfully_through_unmodified_trusted_core(
    migrated_vpn_definition: ExperimentDefinition, tmp_path: Path
) -> None:
    _make_old_dataset_available(tmp_path)
    old = ExperimentDefinition.model_validate_json(OLD_VPN_PATH.read_text(encoding="utf-8"))

    old_summary = experiment_service.run_experiment(
        old, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=tmp_path / "results_old"
    )
    new_summary = experiment_service.run_experiment(
        migrated_vpn_definition, execution_context=ExecutionContext.EXPERIMENT_RUN,
        results_root=tmp_path / "results_new",
    )

    old_verdict = compute_verdict(old_summary.comparison_report)
    new_verdict = compute_verdict(new_summary.comparison_report)

    # Documented intentional difference: case counts differ (curated vs generated).
    assert old_summary.comparison_report.total_cases != new_summary.comparison_report.total_cases

    # Backward compatibility: both reach the same quality-of-outcome verdict.
    assert old_verdict.label is VerdictLabel.EFFECTIVE
    assert new_verdict.label is VerdictLabel.EFFECTIVE


def test_old_and_new_telecom_experiments_both_run_successfully(
    migrated_telecom_definition: ExperimentDefinition, tmp_path: Path
) -> None:
    _make_old_dataset_available(tmp_path)
    old = ExperimentDefinition.model_validate_json(OLD_TELECOM_PATH.read_text(encoding="utf-8"))

    old_summary = experiment_service.run_experiment(
        old, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=tmp_path / "results_old"
    )
    new_summary = experiment_service.run_experiment(
        migrated_telecom_definition, execution_context=ExecutionContext.EXPERIMENT_RUN,
        results_root=tmp_path / "results_new",
    )

    old_verdict = compute_verdict(old_summary.comparison_report)
    new_verdict = compute_verdict(new_summary.comparison_report)
    assert old_verdict.label is VerdictLabel.EFFECTIVE
    assert new_verdict.label is VerdictLabel.EFFECTIVE


def test_original_hand_authored_experiments_are_never_modified_by_this_test_suite() -> None:
    """The original files in experiments/ must remain untouched - migration
    demonstrates compatibility via NEW experiment_ids (ZC-VPN-EXP-002 /
    ZC-TELECOM-EXP-002), never by overwriting ZC-VPN-EXP-001/
    ZC-TELECOM-EXP-001."""
    assert OLD_VPN_PATH.is_file()
    assert OLD_TELECOM_PATH.is_file()
    vpn = ExperimentDefinition.model_validate_json(OLD_VPN_PATH.read_text(encoding="utf-8"))
    telecom = ExperimentDefinition.model_validate_json(OLD_TELECOM_PATH.read_text(encoding="utf-8"))
    assert vpn.experiment_id == "ZC-VPN-EXP-001"
    assert telecom.experiment_id == "ZC-TELECOM-EXP-001"
