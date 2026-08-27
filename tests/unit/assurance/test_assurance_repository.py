"""Exercises AssuranceRepository against the in-memory SQLite fixture -
asset CRUD/matching (Step 7), control/version/validation persistence
(Step 8), and revalidation-candidate duplicate prevention (Step 11)."""

from datetime import UTC, datetime

from zeroshield.assurance.models import Asset, ControlValidation, RevalidationCandidate
from zeroshield.assurance.repository import AssuranceRepository, control_id_for
from zeroshield.db.models import AffectedProductORM, ProductORM, VulnerabilityORM

NOW = datetime.now(UTC)


def _asset(**overrides: object) -> Asset:
    base = {
        "asset_id": "AST-1", "name": "HQ Gateway", "vendor": "Fortinet", "product": "FortiOS",
        "environment": "production", "exposure": "internet_facing", "criticality": "critical",
        "created_at": NOW, "updated_at": NOW,
    }
    base.update(overrides)
    return Asset(**base)


def test_create_and_get_asset_round_trips(assurance_repo: AssuranceRepository) -> None:
    assurance_repo.create_asset(_asset())
    fetched = assurance_repo.get_asset("AST-1")
    assert fetched is not None
    assert fetched.vendor == "Fortinet"
    assert fetched.active is True


def test_get_unknown_asset_returns_none(assurance_repo: AssuranceRepository) -> None:
    assert assurance_repo.get_asset("AST-999") is None


def test_list_assets_filters_by_active_and_vendor(assurance_repo: AssuranceRepository) -> None:
    assurance_repo.create_asset(_asset(asset_id="AST-1", vendor="Fortinet"))
    assurance_repo.create_asset(_asset(asset_id="AST-2", vendor="Cisco", active=False))

    active_only = assurance_repo.list_assets(active=True)
    assert [a.asset_id for a in active_only] == ["AST-1"]

    fortinet_only = assurance_repo.list_assets(vendor="fortinet")
    assert [a.asset_id for a in fortinet_only] == ["AST-1"]


def test_update_asset_changes_fields_and_bumps_updated_at(assurance_repo: AssuranceRepository) -> None:
    assurance_repo.create_asset(_asset())
    updated = assurance_repo.update_asset("AST-1", criticality="low", active=False)
    assert updated is not None
    assert updated.criticality == "low"
    assert updated.active is False
    assert updated.updated_at >= NOW


def test_list_potentially_affected_assets_matches_by_vendor_and_product(assurance_repo: AssuranceRepository) -> None:
    # Seed the intelligence-side product/affected_product tables directly (the
    # same tables GET /vulnerabilities' `product` filter already reads).
    with assurance_repo._session_factory() as session:
        session.add(VulnerabilityORM(cve_id="CVE-2024-00001", kev_listed=False, first_seen_at=NOW, last_updated_at=NOW))
        product = ProductORM(vendor="Fortinet", name="FortiOS")
        session.add(product)
        session.flush()
        session.add(AffectedProductORM(cve_id="CVE-2024-00001", product_id=product.id))
        session.commit()

    assurance_repo.create_asset(_asset(asset_id="AST-1", vendor="Fortinet", product="FortiOS"))
    assurance_repo.create_asset(_asset(asset_id="AST-2", vendor="Cisco", product="ASA"))

    affected = assurance_repo.list_potentially_affected_assets("CVE-2024-00001")
    assert [a.asset_id for a in affected] == ["AST-1"]


def test_list_potentially_affected_assets_empty_when_no_product_data(assurance_repo: AssuranceRepository) -> None:
    assurance_repo.create_asset(_asset())
    assert assurance_repo.list_potentially_affected_assets("CVE-9999-99999") == []


def test_control_id_for_is_deterministic_and_domain_scoped() -> None:
    assert control_id_for("VPN", "strict_mitigation") == "VPN:strict_mitigation"
    assert control_id_for("VPN", "strict_mitigation") != control_id_for("TELECOM", "strict_mitigation")


def test_get_or_create_control_is_idempotent(assurance_repo: AssuranceRepository) -> None:
    first = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_mitigation", name="X")
    second = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_mitigation", name="Y")
    assert first.control_id == second.control_id
    assert first.name == "X"  # first write wins, no silent overwrite


def test_get_or_create_control_version_is_idempotent_per_label(assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_mitigation", name="X")
    v1 = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn",
        template_id="t", template_version="1.0.0",
    )
    v2 = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn",
        template_id="t", template_version="1.0.0",
    )
    v3 = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="2.0.0", domain_pack_id="vpn",
        template_id="t", template_version="1.0.0",
    )
    assert v1.version_id == v2.version_id
    assert v1.version_id != v3.version_id


def _validation(control_id: str, version_id: str, **overrides: object) -> ControlValidation:
    base = {
        "validation_id": "VAL-1", "control_id": control_id, "version_id": version_id,
        "experiment_id": "ZC-VPN-EXP-001", "baseline_run_id": "RUN-1", "mitigation_run_id": "RUN-2",
        "total_cases": 10, "block_rate_improvement": 0.5, "false_positive_rate": 0.0,
        "false_negative_rate": 0.0, "valid_acceptance_rate": 1.0, "parser_reach_rate": 0.0,
        "latency_overhead_ms": 1.0, "verdict_label": "effective", "validated_at": NOW,
    }
    base.update(overrides)
    return ControlValidation(**base)


def test_record_and_list_validations_are_append_only_and_ordered(assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_mitigation", name="X")
    version = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn", template_id="t", template_version="1.0.0"
    )
    from datetime import timedelta

    v1 = _validation(control.control_id, version.version_id, validation_id="VAL-1", validated_at=NOW - timedelta(days=1))
    v2 = _validation(control.control_id, version.version_id, validation_id="VAL-2", validated_at=NOW)
    assurance_repo.record_validation(v2)
    assurance_repo.record_validation(v1)  # inserted out of order

    ordered = assurance_repo.list_validations(control.control_id)
    assert [v.validation_id for v in ordered] == ["VAL-1", "VAL-2"]  # still oldest -> newest


def test_find_pending_candidate_prevents_duplicates(assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_mitigation", name="X")
    assert assurance_repo.find_pending_candidate(control_id=control.control_id, trigger_type="scheduled") is None

    assurance_repo.create_candidate(
        RevalidationCandidate(
            candidate_id="REVAL-1", control_id=control.control_id, trigger_type="scheduled",
            trigger_detail="d", status="pending", created_at=NOW,
        )
    )
    existing = assurance_repo.find_pending_candidate(control_id=control.control_id, trigger_type="scheduled")
    assert existing is not None
    assert existing.candidate_id == "REVAL-1"


def test_find_pending_candidate_ignores_non_pending(assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_mitigation", name="X")
    assurance_repo.create_candidate(
        RevalidationCandidate(
            candidate_id="REVAL-1", control_id=control.control_id, trigger_type="scheduled",
            trigger_detail="d", status="pending", created_at=NOW,
        )
    )
    assurance_repo.update_candidate_status("REVAL-1", status="approved", reviewed_by="alice", review_note=None)
    # Now that the candidate is resolved, the same trigger should be creatable again.
    assert assurance_repo.find_pending_candidate(control_id=control.control_id, trigger_type="scheduled") is None


def test_find_pending_candidate_ignores_changing_trigger_detail_text(assurance_repo: AssuranceRepository) -> None:
    """Regression test for the day-over-day dedup bug: a scheduled
    candidate's trigger_detail embeds `age.days`, which increments every
    day the control stays unrevalidated. Dedup must key on
    (control_id, trigger_type) only, never on that ever-changing text, or a
    fresh "duplicate" would slip through on every subsequent scan."""
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_mitigation", name="X")
    assurance_repo.create_candidate(
        RevalidationCandidate(
            candidate_id="REVAL-1", control_id=control.control_id, trigger_type="scheduled",
            trigger_detail="Last validated 90 days ago (window: 90 days).", status="pending", created_at=NOW,
        )
    )
    # A later scan would compute a *different* trigger_detail string (91 days, 92 days, ...).
    existing = assurance_repo.find_pending_candidate(control_id=control.control_id, trigger_type="scheduled")
    assert existing is not None
    assert existing.candidate_id == "REVAL-1"


def test_save_and_review_ai_assessment(assurance_repo: AssuranceRepository) -> None:
    record = assurance_repo.save_assessment(
        assessment_type="mitigation_gap", subject_type="vulnerability", subject_id="CVE-2024-00001",
        payload={"gaps": ["no credential rotation guidance"], "rationale": "x", "confidence": 0.7,
                 "source_ids": [], "provider": "gemini", "model": "gemini-2.5-flash"},
        confidence=0.7,
    )
    assert record.reviewed is False
    reviewed = assurance_repo.mark_assessment_reviewed(record.assessment_id, reviewed_by="alice", review_note="looks right")
    assert reviewed is not None
    assert reviewed.reviewed is True
    assert reviewed.reviewed_by == "alice"
