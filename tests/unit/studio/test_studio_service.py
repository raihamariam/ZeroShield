from pathlib import Path

from zeroshield.generators import VPNGeneratorConfig
from zeroshield.models import CVEReference
from zeroshield.models.enums import ApprovalStatus, ExperimentVersionStatus, RootCauseCategory
from zeroshield.studio import service
from zeroshield.studio.builder import ImmutableVersionError
from zeroshield.studio.repository import ExperimentVersionRepository


def _cve() -> CVEReference:
    return CVEReference(
        cve_id="CVE-2024-21762", domain="VPN", cvss_score=9.8, cisa_kev=True, epss_score=0.83,
        trust_boundary="x", root_cause="memory_safety_failure", vendor_mitigation="x",
        mitigation_gap="x", source_urls=["https://example.com"], retrieved_date="2026-07-13",
    )


def _draft_kwargs(**overrides: object) -> dict:
    base = {
        "experiment_id": "ZC-VPN-EXP-870", "version_number": 1, "title": "t", "description": "d",
        "related_cves": [_cve()], "domain_pack_id": "vpn", "template_id": "vpn_schema_canonicalisation",
        "template_version": "1.0.0", "dataset_config": VPNGeneratorConfig(), "seed": 1,
        "failure_pattern": "p", "root_cause": RootCauseCategory.MEMORY_SAFETY_FAILURE,
        "vendor_mitigation": "x", "mitigation_gap": "x", "research_question": "q?", "hypothesis": "h",
        "created_by": "researcher1",
    }
    base.update(overrides)
    return base


def test_create_draft_persists_to_repository(version_repo: ExperimentVersionRepository) -> None:
    version = service.create_draft(version_repo, **_draft_kwargs())
    assert version_repo.get_version(version.version_id) is not None


def test_edit_persists_updated_content(version_repo: ExperimentVersionRepository) -> None:
    version = service.create_draft(version_repo, **_draft_kwargs())
    updated = service.edit(version_repo, version.version_id, title="new title")
    assert updated.definition.title == "new title"
    assert version_repo.get_version(version.version_id).definition.title == "new title"


def test_edit_after_submission_raises(version_repo: ExperimentVersionRepository) -> None:
    version = service.create_draft(version_repo, **_draft_kwargs())
    service.submit_for_review(version_repo, version.version_id, actor="researcher1")
    try:
        service.edit(version_repo, version.version_id, title="should fail")
        raise AssertionError("expected ImmutableVersionError")
    except ImmutableVersionError:
        pass


def test_full_workflow_via_service_layer_materialises_on_approve(
    version_repo: ExperimentVersionRepository, tmp_path: Path
) -> None:
    version = service.create_draft(version_repo, **_draft_kwargs())
    service.submit_for_review(version_repo, version.version_id, actor="researcher1")
    service.start_review(version_repo, version.version_id, actor="reviewer1")
    approved = service.approve(
        version_repo, version.version_id, actor="reviewer1", reason="ok", experiments_dir=tmp_path / "experiments"
    )
    assert approved.status is ExperimentVersionStatus.APPROVED
    assert approved.definition.approval_status is ApprovalStatus.APPROVED
    assert (tmp_path / "experiments" / "ZC-VPN-EXP-870.json").is_file()

    history = version_repo.get_approval_history(version.version_id)
    assert [h.to_status for h in history] == [
        ExperimentVersionStatus.READY_FOR_REVIEW, ExperimentVersionStatus.UNDER_REVIEW, ExperimentVersionStatus.APPROVED
    ]


def test_reject_does_not_materialise_anything(version_repo: ExperimentVersionRepository, tmp_path: Path) -> None:
    version = service.create_draft(version_repo, **_draft_kwargs())
    service.submit_for_review(version_repo, version.version_id, actor="researcher1")
    service.start_review(version_repo, version.version_id, actor="reviewer1")
    rejected = service.reject(version_repo, version.version_id, actor="reviewer1", reason="no")
    assert rejected.status is ExperimentVersionStatus.REJECTED
    assert not (tmp_path / "experiments").exists()


def test_next_version_number_increments(version_repo: ExperimentVersionRepository) -> None:
    assert service.next_version_number(version_repo, "ZC-VPN-EXP-871") == 1
    service.create_draft(version_repo, **_draft_kwargs(experiment_id="ZC-VPN-EXP-871"))
    assert service.next_version_number(version_repo, "ZC-VPN-EXP-871") == 2
