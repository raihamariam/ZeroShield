"""Step 11: trigger detection and duplicate prevention. Uses the real
ZC-VPN-EXP-001.json experiment (mitigation_strategy=
strict_schema_canonicalisation_mitigation, related CVE CVE-2024-21762) so
find_experiment() resolves it exactly as the worker would."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from zeroshield.assurance.control_binding import bind_experiment_to_control
from zeroshield.assurance.models import ControlValidation
from zeroshield.assurance.repository import AssuranceRepository, control_id_for
from zeroshield.assurance.revalidation import scan
from zeroshield.experiments import find_experiment
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.models import ComparisonReport, ExperimentMetrics
from zeroshield.models.enums import Domain
from zeroshield.models.vulnerability import (
    VendorAdvisory,
    Vulnerability,
    VulnerabilityHistoryEntry,
    VulnerabilitySourceName,
)
from zeroshield.worker.processor import record_control_validation_and_check_regression

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"

NOW = datetime.now(UTC)
CONTROL_ID = control_id_for("VPN", "strict_schema_canonicalisation_mitigation")
CVE_ID = "CVE-2024-21762"


def _seed_validated_control(repo: AssuranceRepository, *, validated_at: datetime, version_label: str = "1.0.0") -> None:
    control = repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_schema_canonicalisation_mitigation", name="X")
    version = repo.get_or_create_control_version(
        control_id=control.control_id, version_label=version_label, domain_pack_id="vpn",
        template_id="vpn_schema_canonicalisation", template_version="1.0.0",
    )
    repo.record_validation(
        ControlValidation(
            validation_id=f"VAL-{version_label}", control_id=control.control_id, version_id=version.version_id,
            experiment_id="ZC-VPN-EXP-001", baseline_run_id="RUN-1", mitigation_run_id="RUN-2", total_cases=10,
            block_rate_improvement=0.6, false_positive_rate=0.0, false_negative_rate=0.0,
            valid_acceptance_rate=1.0, parser_reach_rate=0.0, latency_overhead_ms=1.0, verdict_label="effective",
            validated_at=validated_at,
        )
    )


def test_scan_with_no_controls_creates_nothing(assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository) -> None:
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert summary.candidates_created == []


def test_scan_with_no_prior_validation_is_a_no_op_for_that_control(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    # A control with zero validations is a first validation, not a revalidation.
    assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="strict_schema_canonicalisation_mitigation", name="X")
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert summary.candidates_created == []


def test_scan_detects_kev_state_change_since_last_validation(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=5))
    vuln_repo.append_history(
        [
            VulnerabilityHistoryEntry(
                cve_id=CVE_ID, source=VulnerabilitySourceName.CISA_KEV, field="kev_listed",
                old_value="False", new_value="True", observed_at=NOW - timedelta(days=1),
            )
        ]
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    kev_candidates = [c for c in summary.candidates_created if c.trigger_type == "kev_state_change"]
    assert len(kev_candidates) == 1
    assert kev_candidates[0].control_id == CONTROL_ID
    assert CVE_ID in kev_candidates[0].trigger_detail


def test_scan_ignores_history_entries_before_last_validation(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    validated_at = NOW - timedelta(days=5)
    _seed_validated_control(assurance_repo, validated_at=validated_at)
    vuln_repo.append_history(
        [
            VulnerabilityHistoryEntry(
                cve_id=CVE_ID, source=VulnerabilitySourceName.CISA_KEV, field="kev_listed",
                old_value="False", new_value="True", observed_at=validated_at - timedelta(days=10),
            )
        ]
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert not any(c.trigger_type == "kev_state_change" for c in summary.candidates_created)


def test_scan_detects_material_epss_change(assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=5))
    vuln_repo.append_history(
        [
            VulnerabilityHistoryEntry(
                cve_id=CVE_ID, source=VulnerabilitySourceName.EPSS, field="epss_score",
                old_value="0.10", new_value="0.85", observed_at=NOW - timedelta(days=1),
            )
        ]
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert any(c.trigger_type == "epss_material_change" for c in summary.candidates_created)


def test_scan_ignores_immaterial_epss_change(assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=5))
    vuln_repo.append_history(
        [
            VulnerabilityHistoryEntry(
                cve_id=CVE_ID, source=VulnerabilitySourceName.EPSS, field="epss_score",
                old_value="0.10", new_value="0.15", observed_at=NOW - timedelta(days=1),
            )
        ]
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert not any(c.trigger_type == "epss_material_change" for c in summary.candidates_created)


def test_scan_detects_scheduled_staleness(assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=200))
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90))
    assert any(c.trigger_type == "scheduled" for c in summary.candidates_created)


def test_scan_does_not_flag_recent_validation_as_stale(assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=5))
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90))
    assert not any(c.trigger_type == "scheduled" for c in summary.candidates_created)


def test_scan_detects_vendor_advisory_update_since_last_validation(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    validated_at = NOW - timedelta(days=5)
    _seed_validated_control(assurance_repo, validated_at=validated_at)
    vuln_repo.upsert_vendor_advisory(
        VendorAdvisory(
            advisory_id="GHSA-new", source=VulnerabilitySourceName.GITHUB_ADVISORY, cve_id=CVE_ID,
            title="Updated guidance", updated_at=NOW - timedelta(days=1),
        )
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    advisory_candidates = [c for c in summary.candidates_created if c.trigger_type == "advisory_update"]
    assert len(advisory_candidates) == 1
    assert CVE_ID in advisory_candidates[0].trigger_detail


def test_scan_ignores_advisory_updates_before_last_validation(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    validated_at = NOW - timedelta(days=5)
    _seed_validated_control(assurance_repo, validated_at=validated_at)
    vuln_repo.upsert_vendor_advisory(
        VendorAdvisory(
            advisory_id="GHSA-old", source=VulnerabilitySourceName.GITHUB_ADVISORY, cve_id=CVE_ID,
            title="Old guidance", updated_at=validated_at - timedelta(days=10),
        )
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert not any(c.trigger_type == "advisory_update" for c in summary.candidates_created)


def test_scan_detects_new_related_cve_via_deterministic_correlation(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    validated_at = NOW - timedelta(days=5)
    _seed_validated_control(assurance_repo, validated_at=validated_at)
    vuln_repo.upsert_vulnerability(
        Vulnerability(
            cve_id=CVE_ID, first_seen_at=validated_at - timedelta(days=30), last_updated_at=validated_at,
            vendor="fortinet", domain_guess=Domain.VPN, cwe_ids=["CWE-306"],
            description="Authentication bypass using an alternate path or channel in FortiOS SSL-VPN.",
        )
    )
    vuln_repo.upsert_vulnerability(
        Vulnerability(
            cve_id="CVE-2025-00001", first_seen_at=NOW - timedelta(days=1), last_updated_at=NOW - timedelta(days=1),
            vendor="fortinet", domain_guess=Domain.VPN, cwe_ids=["CWE-306"],
            description="Authentication bypass using an alternate path or channel in FortiOS SSL-VPN.",
        )
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    new_cve_candidates = [c for c in summary.candidates_created if c.trigger_type == "new_related_cve"]
    assert len(new_cve_candidates) == 1
    assert "CVE-2025-00001" in new_cve_candidates[0].trigger_detail


def test_scan_ignores_unrelated_or_stale_candidates_for_new_related_cve(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    validated_at = NOW - timedelta(days=5)
    _seed_validated_control(assurance_repo, validated_at=validated_at)
    vuln_repo.upsert_vulnerability(
        Vulnerability(
            cve_id=CVE_ID, first_seen_at=validated_at - timedelta(days=30), last_updated_at=validated_at,
            vendor="fortinet", domain_guess=Domain.VPN, cwe_ids=["CWE-306"], description="FortiOS SSL-VPN bypass.",
        )
    )
    # Unrelated: different vendor/domain/CWE, no text overlap - should score below threshold.
    vuln_repo.upsert_vulnerability(
        Vulnerability(
            cve_id="CVE-2025-00002", first_seen_at=NOW - timedelta(days=1), last_updated_at=NOW - timedelta(days=1),
            vendor="acme", domain_guess=Domain.TELECOM, cwe_ids=["CWE-89"], description="Unrelated SQL injection.",
        )
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert not any(c.trigger_type == "new_related_cve" for c in summary.candidates_created)


def test_scan_detects_unvalidated_new_control_version(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=5), version_label="1.0.0")
    control = assurance_repo.get_control(CONTROL_ID)
    assert control is not None
    assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="2.0.0", domain_pack_id="vpn",
        template_id="vpn_schema_canonicalisation", template_version="1.0.0",
    )
    summary = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR)
    assert any(c.trigger_type == "version_change" for c in summary.candidates_created)


def test_scan_never_creates_duplicate_pending_candidates(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=200))
    first = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90))
    second = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90))
    assert len(first.candidates_created) >= 1
    assert second.candidates_created == []
    pending = assurance_repo.list_candidates(status="pending")
    scheduled = [c for c in pending if c.trigger_type == "scheduled" and c.control_id == CONTROL_ID]
    assert len(scheduled) == 1


def test_scan_never_creates_duplicate_scheduled_candidate_across_days(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    """Regression test: a scheduled candidate's trigger_detail embeds
    `age.days`, which is different on every subsequent day the control
    stays unrevalidated. A scan run "today" and a scan run "tomorrow" must
    still be recognised as the same pending candidate, not create a second
    one - unlike test_scan_never_creates_duplicate_pending_candidates
    above, which scans twice at the same instant and would not have caught
    this."""
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=200))
    day_one = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90), now=NOW)
    day_two = scan(
        assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90), now=NOW + timedelta(days=1)
    )
    assert len(day_one.candidates_created) >= 1
    assert day_two.candidates_created == []
    pending = assurance_repo.list_candidates(status="pending")
    scheduled = [c for c in pending if c.trigger_type == "scheduled" and c.control_id == CONTROL_ID]
    assert len(scheduled) == 1


def test_scan_recreates_candidate_after_prior_one_is_resolved(
    assurance_repo: AssuranceRepository, vuln_repo: VulnerabilityRepository
) -> None:
    _seed_validated_control(assurance_repo, validated_at=NOW - timedelta(days=200))
    first = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90))
    scheduled = next(c for c in first.candidates_created if c.trigger_type == "scheduled")
    assurance_repo.update_candidate_status(scheduled.candidate_id, status="dismissed", reviewed_by="alice", review_note=None)

    second = scan(assurance_repo, vuln_repo, EXPERIMENTS_DIR, staleness_window=timedelta(days=90))
    assert any(c.trigger_type == "scheduled" for c in second.candidates_created)


# -- regression -> revalidation candidate (final release gap-closure pass) --
# Unlike every trigger above, "regression" is not raised by scan() - it's
# raised synchronously by zeroshield.worker.processor.
# record_control_validation_and_check_regression, immediately after a
# completed run's ControlValidation is recorded. Tested here anyway since
# it shares this module's create_candidate_if_new() and the same
# RevalidationCandidate/pending/dedup contract every other trigger has.


def _metrics(run_id: str, **overrides: float) -> ExperimentMetrics:
    base = {
        "run_id": run_id, "processing_success_rate": 1.0, "block_rate": 0.0, "valid_acceptance_rate": 1.0,
        "false_positive_rate": 0.0, "false_negative_rate": 0.0, "parser_reach_rate": 0.0, "mean_latency_ms": 1.0,
        "log_completeness_rate": 0.0, "calculated_at": NOW, "calculation_version": "1.0.0",
    }
    base.update(overrides)
    return ExperimentMetrics(**base)


def _comparison(*, run_suffix: str, block_rate_improvement: float, total_cases: int = 20) -> ComparisonReport:
    baseline_run_id, mitigation_run_id = f"RUN-{run_suffix}01", f"RUN-{run_suffix}02"
    return ComparisonReport(
        experiment_id="ZC-VPN-EXP-001", baseline_run_id=baseline_run_id, mitigation_run_id=mitigation_run_id,
        total_cases=total_cases, baseline_metrics=_metrics(baseline_run_id, block_rate=0.0),
        mitigation_metrics=_metrics(mitigation_run_id, block_rate=block_rate_improvement),
        block_rate_improvement=block_rate_improvement, latency_overhead_ms=1.0,
        limitations=["synthetic only"], generated_at=NOW,
    )


def _record(assurance_repo: AssuranceRepository, *, run_suffix: str, block_rate_improvement: float) -> None:
    experiment = find_experiment(EXPERIMENTS_DIR, "ZC-VPN-EXP-001")
    assert experiment is not None
    binding = bind_experiment_to_control(assurance_repo, experiment)
    summary = SimpleNamespace(
        comparison_report=_comparison(run_suffix=run_suffix, block_rate_improvement=block_rate_improvement)
    )
    record_control_validation_and_check_regression(assurance_repo, binding=binding, experiment=experiment, summary=summary)


def test_first_validation_of_a_version_creates_no_regression_candidate(assurance_repo: AssuranceRepository) -> None:
    _record(assurance_repo, run_suffix="1", block_rate_improvement=0.9)
    pending = assurance_repo.list_candidates(status="pending")
    assert [c for c in pending if c.trigger_type == "regression"] == []


def test_a_real_deterministic_regression_creates_a_pending_regression_candidate(
    assurance_repo: AssuranceRepository,
) -> None:
    _record(assurance_repo, run_suffix="1", block_rate_improvement=0.9)  # healthy baseline validation
    _record(assurance_repo, run_suffix="2", block_rate_improvement=0.3)  # drop of 0.6 >> the 0.10 threshold

    pending = assurance_repo.list_candidates(status="pending")
    regression_candidates = [c for c in pending if c.trigger_type == "regression" and c.control_id == CONTROL_ID]
    assert len(regression_candidates) == 1
    assert "block_rate_improvement" in regression_candidates[0].trigger_detail
    assert regression_candidates[0].status == "pending"
    # AI played no part - both the regression decision and the candidate it
    # produced come from deterministic code only (detect_regressions +
    # create_candidate_if_new, both called with no AIProvider in scope here).


def test_a_second_regression_does_not_duplicate_the_pending_candidate(assurance_repo: AssuranceRepository) -> None:
    _record(assurance_repo, run_suffix="1", block_rate_improvement=0.9)
    _record(assurance_repo, run_suffix="2", block_rate_improvement=0.3)  # first regression
    _record(assurance_repo, run_suffix="3", block_rate_improvement=0.1)  # still bad - a second regression vs. run 2

    pending = assurance_repo.list_candidates(status="pending")
    regression_candidates = [c for c in pending if c.trigger_type == "regression" and c.control_id == CONTROL_ID]
    assert len(regression_candidates) == 1


def test_regression_candidate_never_auto_executes_a_run(assurance_repo: AssuranceRepository) -> None:
    """The candidate reaches pending and stops there - approving it is a
    separate, explicit human action (zeroshield.api.routes.revalidation),
    and even "approved" only unlocks submitting an ordinary run through the
    normal Experiments/Runs path, never runs one itself."""
    _record(assurance_repo, run_suffix="1", block_rate_improvement=0.9)
    _record(assurance_repo, run_suffix="2", block_rate_improvement=0.3)

    pending = assurance_repo.list_candidates(status="pending")
    regression_candidate = next(c for c in pending if c.trigger_type == "regression")
    assert regression_candidate.status == "pending"
    assert regression_candidate.reviewed_by is None
    assert regression_candidate.reviewed_at is None


def test_an_improvement_does_not_create_a_regression_candidate(assurance_repo: AssuranceRepository) -> None:
    _record(assurance_repo, run_suffix="1", block_rate_improvement=0.3)
    _record(assurance_repo, run_suffix="2", block_rate_improvement=0.9)  # better, not worse

    pending = assurance_repo.list_candidates(status="pending")
    assert [c for c in pending if c.trigger_type == "regression"] == []
