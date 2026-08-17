from pathlib import Path

from zeroshield.generators import VPNGeneratorConfig
from zeroshield.models import CVEReference
from zeroshield.models.enums import ExperimentVersionStatus, RootCauseCategory
from zeroshield.studio.approval import transition
from zeroshield.studio.builder import build_experiment_draft
from zeroshield.studio.repository import ExperimentVersionRepository


def _cve() -> CVEReference:
    return CVEReference(
        cve_id="CVE-2024-21762", domain="VPN", cvss_score=9.8, cisa_kev=True, epss_score=0.83,
        trust_boundary="x", root_cause="memory_safety_failure", vendor_mitigation="x",
        mitigation_gap="x", source_urls=["https://example.com"], retrieved_date="2026-07-13",
    )


def _draft(tmp_path: Path, experiment_id: str = "ZC-VPN-EXP-802", version_number: int = 1):
    return build_experiment_draft(
        experiment_id=experiment_id, version_number=version_number, title="t", description="d",
        related_cves=[_cve()], domain_pack_id="vpn", template_id="vpn_schema_canonicalisation",
        template_version="1.0.0", dataset_config=VPNGeneratorConfig(), seed=1,
        failure_pattern="p", root_cause=RootCauseCategory.MEMORY_SAFETY_FAILURE,
        vendor_mitigation="x", mitigation_gap="x", research_question="q?", hypothesis="h",
        created_by="researcher1",
    )


def test_save_and_get_version_round_trips(version_repo: ExperimentVersionRepository, tmp_path: Path) -> None:
    version = _draft(tmp_path)
    version_repo.save_version(version)
    fetched = version_repo.get_version(version.version_id)
    assert fetched is not None
    assert fetched.definition.title == "t"
    assert fetched.status is ExperimentVersionStatus.DRAFT


def test_get_unknown_version_returns_none(version_repo: ExperimentVersionRepository) -> None:
    assert version_repo.get_version("does-not-exist") is None


def test_save_version_updates_existing_row(version_repo: ExperimentVersionRepository, tmp_path: Path) -> None:
    version = _draft(tmp_path)
    version_repo.save_version(version)
    updated = version.model_copy(update={"status": ExperimentVersionStatus.READY_FOR_REVIEW})
    version_repo.save_version(updated)
    fetched = version_repo.get_version(version.version_id)
    assert fetched.status is ExperimentVersionStatus.READY_FOR_REVIEW


def test_list_versions_filters_by_experiment_id_and_status(
    version_repo: ExperimentVersionRepository, tmp_path: Path
) -> None:
    v1 = _draft(tmp_path, experiment_id="ZC-VPN-EXP-810", version_number=1)
    v2 = _draft(tmp_path, experiment_id="ZC-VPN-EXP-811", version_number=1)
    version_repo.save_version(v1)
    version_repo.save_version(v2)

    only_810 = version_repo.list_versions(experiment_id="ZC-VPN-EXP-810")
    assert [v.experiment_id for v in only_810] == ["ZC-VPN-EXP-810"]

    only_draft = version_repo.list_versions(status=ExperimentVersionStatus.DRAFT)
    assert len(only_draft) == 2


def test_latest_version_number_tracks_across_versions(
    version_repo: ExperimentVersionRepository, tmp_path: Path
) -> None:
    assert version_repo.latest_version_number("ZC-VPN-EXP-820") == 0
    v1 = _draft(tmp_path, experiment_id="ZC-VPN-EXP-820", version_number=1)
    version_repo.save_version(v1)
    assert version_repo.latest_version_number("ZC-VPN-EXP-820") == 1
    v2 = _draft(tmp_path, experiment_id="ZC-VPN-EXP-820", version_number=2)
    version_repo.save_version(v2)
    assert version_repo.latest_version_number("ZC-VPN-EXP-820") == 2


def test_approval_history_append_and_ordered(
    version_repo: ExperimentVersionRepository, tmp_path: Path
) -> None:
    version = _draft(tmp_path)
    version_repo.save_version(version)
    version, d1 = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="researcher1")
    version_repo.append_approval_decision(d1)
    version, d2 = transition(version, ExperimentVersionStatus.UNDER_REVIEW, actor="reviewer1")
    version_repo.append_approval_decision(d2)

    history = version_repo.get_approval_history(version.version_id)
    assert [h.to_status for h in history] == [
        ExperimentVersionStatus.READY_FOR_REVIEW, ExperimentVersionStatus.UNDER_REVIEW
    ]


def test_old_version_remains_immutable_and_retrievable_after_new_version_created(
    version_repo: ExperimentVersionRepository, tmp_path: Path
) -> None:
    """Editing creates a new version (Step 4) - proven at the repository level:
    saving version 2 must never alter version 1's stored content."""
    v1 = _draft(tmp_path, experiment_id="ZC-VPN-EXP-830", version_number=1)
    version_repo.save_version(v1)
    v2 = build_experiment_draft(
        experiment_id="ZC-VPN-EXP-830", version_number=2, title="revised title", description="d",
        related_cves=[_cve()], domain_pack_id="vpn", template_id="vpn_schema_canonicalisation",
        template_version="1.0.0", dataset_config=VPNGeneratorConfig(), seed=1,
        failure_pattern="p", root_cause=RootCauseCategory.MEMORY_SAFETY_FAILURE,
        vendor_mitigation="x", mitigation_gap="x", research_question="q?", hypothesis="h",
        created_by="researcher1",
    )
    version_repo.save_version(v2)

    fetched_v1 = version_repo.get_version(v1.version_id)
    fetched_v2 = version_repo.get_version(v2.version_id)
    assert fetched_v1.definition.title == "t"
    assert fetched_v2.definition.title == "revised title"
    assert len(version_repo.list_versions(experiment_id="ZC-VPN-EXP-830")) == 2
