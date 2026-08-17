"""Step 10: experiment builder tests."""

from pathlib import Path

import pytest

from zeroshield.generators import TelecomGeneratorConfig, VPNGeneratorConfig
from zeroshield.models import CVEReference
from zeroshield.models.enums import ApprovalStatus, ExperimentVersionStatus, RootCauseCategory
from zeroshield.studio.builder import (
    ExperimentBuilderError,
    ImmutableVersionError,
    build_experiment_draft,
    edit_draft,
    materialise_to_experiments_dir,
)


def _cve(cve_id: str = "CVE-2024-21762", domain: str = "VPN") -> CVEReference:
    return CVEReference(
        cve_id=cve_id, domain=domain, cvss_score=9.8, cisa_kev=True, epss_score=0.83,
        trust_boundary="x", root_cause="memory_safety_failure", vendor_mitigation="x",
        mitigation_gap="x", source_urls=["https://example.com"], retrieved_date="2026-07-13",
    )


def _draft_kwargs(tmp_path: Path, **overrides: object) -> dict:
    base = {
        "experiment_id": "ZC-VPN-EXP-800", "version_number": 1, "title": "t", "description": "d",
        "related_cves": [_cve()], "domain_pack_id": "vpn", "template_id": "vpn_schema_canonicalisation",
        "template_version": "1.0.0", "dataset_config": VPNGeneratorConfig(), "seed": 1,
        "failure_pattern": "p", "root_cause": RootCauseCategory.MEMORY_SAFETY_FAILURE,
        "vendor_mitigation": "x", "mitigation_gap": "x", "research_question": "q?", "hypothesis": "h",
        "created_by": "researcher1",
    }
    base.update(overrides)
    return base


def test_build_experiment_draft_produces_valid_definition(tmp_path: Path) -> None:
    version = build_experiment_draft(**_draft_kwargs(tmp_path))
    assert version.status is ExperimentVersionStatus.DRAFT
    assert version.definition.approval_status is ApprovalStatus.DRAFT
    assert version.definition.baseline_strategy == "weak_schema_length_baseline"
    assert version.definition.mitigation_strategy == "strict_schema_canonicalisation_mitigation"
    assert version.definition.dataset_path.is_file()


def test_build_experiment_draft_telecom(tmp_path: Path) -> None:
    version = build_experiment_draft(
        **_draft_kwargs(
            tmp_path, experiment_id="ZC-TELECOM-EXP-800", domain_pack_id="telecom",
            template_id="telecom_grammar_state_machine", template_version="1.0.0",
            dataset_config=TelecomGeneratorConfig(), related_cves=[_cve(cve_id="CVE-2023-24033", domain="TELECOM")],
        )
    )
    assert version.definition.domain.value == "TELECOM"
    assert version.definition.baseline_strategy == "weak_mandatory_field_state_baseline"


def test_build_experiment_draft_same_seed_and_config_reuses_same_dataset_file(tmp_path: Path) -> None:
    kwargs = _draft_kwargs(tmp_path)
    v1 = build_experiment_draft(**kwargs)
    v2 = build_experiment_draft(**{**kwargs, "version_number": 2})
    assert v1.definition.dataset_path == v2.definition.dataset_path


def test_build_experiment_draft_unknown_domain_pack_raises(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="no registered domain pack"):
        build_experiment_draft(**_draft_kwargs(tmp_path, domain_pack_id="does_not_exist"))


def test_build_experiment_draft_unknown_template_raises(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="no registered template"):
        build_experiment_draft(**_draft_kwargs(tmp_path, template_id="does_not_exist"))


def test_build_experiment_draft_mismatched_domain_pack_and_template_raises(tmp_path: Path) -> None:
    with pytest.raises(ExperimentBuilderError, match="belongs to domain pack"):
        build_experiment_draft(
            **_draft_kwargs(
                tmp_path, domain_pack_id="telecom", template_id="vpn_schema_canonicalisation",
                dataset_config=TelecomGeneratorConfig(),
            )
        )


def test_edit_draft_updates_content_while_draft(tmp_path: Path) -> None:
    version = build_experiment_draft(**_draft_kwargs(tmp_path))
    updated = edit_draft(version, title="new title")
    assert updated.definition.title == "new title"
    assert updated.status is ExperimentVersionStatus.DRAFT


def test_edit_draft_raises_once_not_draft(tmp_path: Path) -> None:
    version = build_experiment_draft(**_draft_kwargs(tmp_path))
    not_draft = version.model_copy(
        update={"status": ExperimentVersionStatus.READY_FOR_REVIEW}
    )
    with pytest.raises(ImmutableVersionError, match="not 'draft'"):
        edit_draft(not_draft, title="should fail")


def test_materialise_to_experiments_dir_writes_runnable_json(tmp_path: Path) -> None:
    version = build_experiment_draft(**_draft_kwargs(tmp_path))
    approved = version.model_copy(
        update={
            "status": ExperimentVersionStatus.APPROVED,
            "definition": version.definition.model_copy(update={"approval_status": ApprovalStatus.APPROVED}),
        }
    )
    experiments_dir = tmp_path / "experiments"
    path = materialise_to_experiments_dir(approved, experiments_dir)
    assert path.is_file()

    from zeroshield.experiments.discovery import find_experiment

    found = find_experiment(experiments_dir, "ZC-VPN-EXP-800")
    assert found is not None
    assert found.approval_status is ApprovalStatus.APPROVED
