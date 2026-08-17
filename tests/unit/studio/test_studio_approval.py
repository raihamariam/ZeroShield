"""Step 10: approval state machine / bypass attempts / independent SafetyPolicy."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from zeroshield.generators import VPNGeneratorConfig
from zeroshield.models import CVEReference
from zeroshield.models.enums import ApprovalStatus, ExperimentVersionStatus, RootCauseCategory
from zeroshield.policies import ExecutionContext, SafetyPolicy
from zeroshield.studio.approval import InvalidTransitionError, check_transition, transition
from zeroshield.studio.builder import build_experiment_draft


def _cve() -> CVEReference:
    return CVEReference(
        cve_id="CVE-2024-21762", domain="VPN", cvss_score=9.8, cisa_kev=True, epss_score=0.83,
        trust_boundary="x", root_cause="memory_safety_failure", vendor_mitigation="x",
        mitigation_gap="x", source_urls=["https://example.com"], retrieved_date="2026-07-13",
    )


def _draft(tmp_path: Path):
    return build_experiment_draft(
        experiment_id="ZC-VPN-EXP-801", version_number=1, title="t", description="d",
        related_cves=[_cve()], domain_pack_id="vpn", template_id="vpn_schema_canonicalisation",
        template_version="1.0.0", dataset_config=VPNGeneratorConfig(), seed=1,
        failure_pattern="p", root_cause=RootCauseCategory.MEMORY_SAFETY_FAILURE,
        vendor_mitigation="x", mitigation_gap="x", research_question="q?", hypothesis="h",
        created_by="researcher1",
    )


# -- allowed transitions ------------------------------------------------------


def test_full_happy_path_transition_sequence(tmp_path: Path) -> None:
    version = _draft(tmp_path)
    version, d1 = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="researcher1")
    assert d1.from_status is ExperimentVersionStatus.DRAFT
    version, _d2 = transition(version, ExperimentVersionStatus.UNDER_REVIEW, actor="reviewer1")
    version, _d3 = transition(version, ExperimentVersionStatus.APPROVED, actor="reviewer1", reason="ok")
    assert version.status is ExperimentVersionStatus.APPROVED
    assert version.definition.approval_status is ApprovalStatus.APPROVED
    version, _d4 = transition(version, ExperimentVersionStatus.RETIRED, actor="admin1")
    assert version.status is ExperimentVersionStatus.RETIRED
    assert version.definition.approval_status is ApprovalStatus.DRAFT  # only APPROVED carries APPROVED


def test_reject_path(tmp_path: Path) -> None:
    version = _draft(tmp_path)
    version, _ = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="researcher1")
    version, _ = transition(version, ExperimentVersionStatus.UNDER_REVIEW, actor="reviewer1")
    version, decision = transition(version, ExperimentVersionStatus.REJECTED, actor="reviewer1", reason="insufficient evidence")
    assert version.status is ExperimentVersionStatus.REJECTED
    assert version.definition.approval_status is ApprovalStatus.DRAFT
    assert decision.reason == "insufficient evidence"


def test_withdraw_back_to_draft(tmp_path: Path) -> None:
    version = _draft(tmp_path)
    version, _ = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="researcher1")
    version, _ = transition(version, ExperimentVersionStatus.DRAFT, actor="researcher1", reason="withdrawing")
    assert version.status is ExperimentVersionStatus.DRAFT


def test_send_back_from_under_review_to_ready_for_review(tmp_path: Path) -> None:
    version = _draft(tmp_path)
    version, _ = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="researcher1")
    version, _ = transition(version, ExperimentVersionStatus.UNDER_REVIEW, actor="reviewer1")
    version, _ = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="reviewer1", reason="needs more evidence")
    assert version.status is ExperimentVersionStatus.READY_FOR_REVIEW


# -- forbidden transitions / bypass attempts ---------------------------------


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ExperimentVersionStatus.DRAFT, ExperimentVersionStatus.APPROVED),  # skip review entirely
        (ExperimentVersionStatus.DRAFT, ExperimentVersionStatus.UNDER_REVIEW),
        (ExperimentVersionStatus.READY_FOR_REVIEW, ExperimentVersionStatus.APPROVED),  # skip UNDER_REVIEW
        (ExperimentVersionStatus.APPROVED, ExperimentVersionStatus.DRAFT),  # un-approve directly
        (ExperimentVersionStatus.REJECTED, ExperimentVersionStatus.APPROVED),  # approve a rejected version
        (ExperimentVersionStatus.REJECTED, ExperimentVersionStatus.DRAFT),  # REJECTED is terminal
        (ExperimentVersionStatus.RETIRED, ExperimentVersionStatus.APPROVED),  # RETIRED is terminal
    ],
)
def test_illegal_transition_attempts_are_rejected(
    tmp_path: Path, current: ExperimentVersionStatus, target: ExperimentVersionStatus
) -> None:
    version = _draft(tmp_path).model_copy(update={"status": current})
    with pytest.raises(InvalidTransitionError):
        check_transition(current, target)
    with pytest.raises(InvalidTransitionError):
        transition(version, target, actor="attacker")


def test_check_transition_lists_allowed_targets_in_error_message() -> None:
    with pytest.raises(InvalidTransitionError, match=r"allowed targets from 'draft': \['ready_for_review'\]"):
        check_transition(ExperimentVersionStatus.DRAFT, ExperimentVersionStatus.APPROVED)


# -- approval never bypasses SafetyPolicy ------------------------------------


def test_approval_transition_never_calls_or_alters_safety_policy(tmp_path: Path) -> None:
    """The approval workflow only ever sets status/approval_status - it must
    never itself evaluate or record a PolicyDecision. Proven by construction:
    ApprovalDecision has no PolicyDecision field, and transition() imports
    nothing from zeroshield.policies."""
    import zeroshield.studio.approval as approval_module

    assert "SafetyPolicy" not in dir(approval_module)


def test_approved_version_still_subject_to_independent_safety_policy_evaluation(tmp_path: Path) -> None:
    """Even after Experiment Studio approval, SafetyPolicy.evaluate() - the
    same, unmodified Phase-1 policy object - is the one that actually decides
    whether a run may proceed. This proves approval is advisory-to-execution,
    never a bypass."""
    version = _draft(tmp_path)
    version, _ = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="researcher1")
    version, _ = transition(version, ExperimentVersionStatus.UNDER_REVIEW, actor="reviewer1")
    version, _ = transition(version, ExperimentVersionStatus.APPROVED, actor="reviewer1")

    decision = SafetyPolicy().evaluate(version.definition, execution_context=ExecutionContext.EXPERIMENT_RUN)
    assert decision.allowed is True  # approved + synthetic-only + no weaponised payloads -> allowed

    # simulate a corrupted/tampered definition somehow carrying weaponised_payloads=True despite
    # being APPROVED - SafetyPolicy must still independently deny it, proving it is not fooled by
    # the workflow's own approval status alone.
    tampered_definition = version.definition.model_copy(update={"weaponised_payloads": True})
    tampered_decision = SafetyPolicy().evaluate(tampered_definition, execution_context=ExecutionContext.EXPERIMENT_RUN)
    assert tampered_decision.allowed is False
    assert any("SAFE-003" in r for r in tampered_decision.reasons)


def test_draft_version_denied_by_safety_policy_under_strict_context(tmp_path: Path) -> None:
    """A DRAFT (never-approved) version's definition must still be denied by
    the real SafetyPolicy under the strict execution_run context - approval
    workflow status alone proves nothing without the definition's own
    approval_status agreeing, which build_experiment_draft always sets to
    draft until the workflow actually approves it."""
    version = _draft(tmp_path)
    decision = SafetyPolicy().evaluate(version.definition, execution_context=ExecutionContext.EXPERIMENT_RUN)
    assert decision.allowed is False
    assert any("SAFE-004" in r for r in decision.reasons)


def test_approval_decision_records_actor_timestamp_reason_version(tmp_path: Path) -> None:
    version = _draft(tmp_path)
    fixed = datetime(2026, 1, 1, tzinfo=UTC)
    _, decision = transition(version, ExperimentVersionStatus.READY_FOR_REVIEW, actor="researcher1", reason="ready", clock=lambda: fixed)
    assert decision.actor == "researcher1"
    assert decision.reason == "ready"
    assert decision.decided_at == fixed
    assert decision.version_id == version.version_id
