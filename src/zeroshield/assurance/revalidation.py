"""Revalidation candidate engine (V2 Phase 5, Step 11).

Flow: trigger -> determine impacted control -> create RevalidationCandidate
-> human review/approval -> normal execution. `scan()` below is the
"trigger -> create candidate" half only; approval and execution are always
separate, explicit human actions (zeroshield.api.routes.revalidation) - see
zeroshield.assurance.models.RevalidationCandidate's docstring for why
nothing here ever queues a run itself.

Detects all six trigger types listed in the phase brief directly from
already-tracked state:

  - kev_state_change / epss_material_change: read straight from
    VulnerabilityHistoryEntry (zeroshield.intelligence.repository.
    get_history), which Step 6 already records field-by-field.
  - version_change: a ControlVersion exists with zero recorded validations
    while an older version of the same control does have validations - a
    genuinely new version nobody has re-validated yet.
  - scheduled: a control's last validation is older than the configured
    staleness window.
  - advisory_update: a VendorAdvisory for one of the control's related CVEs
    has an updated_at/published_at newer than the control's last
    validation (zeroshield.intelligence.repository.get_advisories_for_cve).
  - new_related_cve: the deterministic correlation engine
    (zeroshield.intelligence.correlation) finds a *newly-observed* CVE
    (last_updated_at after the control's last validation) that scores
    highly against one of the control's already-validated CVEs. This is
    the same structured-feature scoring GET /vulnerabilities/{cve}/
    correlations uses - never a fuzzy/AI match - bounded to candidates
    already in the same domain to keep each scan cheap and explainable.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeroshield.assurance.models import RevalidationCandidate, RevalidationTrigger
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.experiments import find_experiment
from zeroshield.intelligence.correlation import rank_correlations
from zeroshield.intelligence.repository import VulnerabilityRepository

_EPSS_MATERIAL_CHANGE = 0.2
_DEFAULT_STALENESS = timedelta(days=90)
_NEW_RELATED_CVE_MIN_SCORE = 60.0


@dataclass(frozen=True)
class ScanSummary:
    candidates_created: list[RevalidationCandidate]
    controls_scanned: int


def _create_if_new(
    repo: AssuranceRepository, *, control_id: str, experiment_id: str | None, trigger_type: str, trigger_detail: str
) -> RevalidationCandidate | None:
    if repo.find_pending_candidate(control_id=control_id, trigger_type=trigger_type):
        return None
    return repo.create_candidate(
        RevalidationCandidate(
            candidate_id=f"REVAL-{uuid.uuid4().hex}", control_id=control_id, experiment_id=experiment_id,
            trigger_type=trigger_type, trigger_detail=trigger_detail, status="pending",
            created_at=datetime.now(UTC),
        )
    )


def scan(
    assurance_repo: AssuranceRepository,
    vuln_repo: VulnerabilityRepository,
    experiments_dir: Path,
    *,
    staleness_window: timedelta = _DEFAULT_STALENESS,
    now: datetime | None = None,
) -> ScanSummary:
    now = now or datetime.now(UTC)
    created: list[RevalidationCandidate] = []

    for control in assurance_repo.list_controls():
        validations = assurance_repo.list_validations(control.control_id)
        if not validations:
            continue  # nothing to revalidate yet - not a revalidation, a first validation
        latest = validations[-1]

        # -- scheduled: staleness -------------------------------------------------
        age = now - latest.validated_at
        if age > staleness_window:
            candidate = _create_if_new(
                assurance_repo, control_id=control.control_id, experiment_id=latest.experiment_id,
                trigger_type=RevalidationTrigger.SCHEDULED,
                trigger_detail=f"Last validated {age.days} days ago (window: {staleness_window.days} days).",
            )
            if candidate:
                created.append(candidate)

        # -- version_change: a newer control version has never been validated -----
        versions = assurance_repo.list_control_versions(control.control_id)
        validated_version_ids = {v.version_id for v in validations}
        for version in versions:
            if version.version_id in validated_version_ids:
                continue
            candidate = _create_if_new(
                assurance_repo, control_id=control.control_id, experiment_id=None,
                trigger_type=RevalidationTrigger.VERSION_CHANGE,
                trigger_detail=f"Control version '{version.version_label}' has never been validated.",
            )
            if candidate:
                created.append(candidate)

        # -- kev_state_change / epss_material_change: from vulnerability history --
        experiment = find_experiment(experiments_dir, latest.experiment_id)
        related_cve_ids = [c.cve_id for c in experiment.related_cves] if experiment is not None else []
        for cve_id in related_cve_ids:
            for entry in vuln_repo.get_history(cve_id):
                if entry.observed_at <= latest.validated_at:
                    continue
                if entry.field == "kev_listed" and str(entry.new_value).strip().lower() == "true":
                    candidate = _create_if_new(
                        assurance_repo, control_id=control.control_id, experiment_id=latest.experiment_id,
                        trigger_type=RevalidationTrigger.KEV_STATE_CHANGE,
                        trigger_detail=f"{cve_id} was added to CISA KEV on {entry.observed_at.date()}.",
                    )
                    if candidate:
                        created.append(candidate)
                elif entry.field == "epss_score":
                    try:
                        old_v = float(entry.old_value) if entry.old_value is not None else None
                        new_v = float(entry.new_value) if entry.new_value is not None else None
                    except ValueError:
                        continue
                    if old_v is not None and new_v is not None and abs(new_v - old_v) >= _EPSS_MATERIAL_CHANGE:
                        candidate = _create_if_new(
                            assurance_repo, control_id=control.control_id, experiment_id=latest.experiment_id,
                            trigger_type=RevalidationTrigger.EPSS_MATERIAL_CHANGE,
                            trigger_detail=f"{cve_id} EPSS moved from {old_v:.2f} to {new_v:.2f} on {entry.observed_at.date()}.",
                        )
                        if candidate:
                            created.append(candidate)

        # -- advisory_update: a vendor advisory for a related CVE changed ----------
        for cve_id in related_cve_ids:
            for advisory in vuln_repo.get_advisories_for_cve(cve_id):
                changed_at = advisory.updated_at or advisory.published_at
                if changed_at is None or changed_at <= latest.validated_at:
                    continue
                candidate = _create_if_new(
                    assurance_repo, control_id=control.control_id, experiment_id=latest.experiment_id,
                    trigger_type=RevalidationTrigger.ADVISORY_UPDATE,
                    trigger_detail=f"Vendor advisory '{advisory.advisory_id}' for {cve_id} was updated on {changed_at.date()}.",
                )
                if candidate:
                    created.append(candidate)

        # -- new_related_cve: a newly-observed CVE correlates strongly with one --
        # -- of this control's already-validated CVEs (deterministic, Step 4) ----
        for cve_id in related_cve_ids:
            subject = vuln_repo.get_vulnerability(cve_id)
            if subject is None:
                continue
            same_domain_candidates, _total = vuln_repo.list_vulnerabilities(domain=subject.domain_guess, limit=200)
            newly_observed = [
                v for v in same_domain_candidates
                if v.cve_id != cve_id and v.cve_id not in related_cve_ids and v.last_updated_at > latest.validated_at
            ]
            for result in rank_correlations(subject, newly_observed, min_score=_NEW_RELATED_CVE_MIN_SCORE, limit=5):
                candidate = _create_if_new(
                    assurance_repo, control_id=control.control_id, experiment_id=latest.experiment_id,
                    trigger_type=RevalidationTrigger.NEW_RELATED_CVE,
                    trigger_detail=(
                        f"{result.cve_id} newly observed and correlates {result.score:.1f}/100 with already-"
                        f"validated {cve_id}. {result.explanation[-1] if result.explanation else ''}"
                    ),
                )
                if candidate:
                    created.append(candidate)

    return ScanSummary(candidates_created=created, controls_scanned=len(assurance_repo.list_controls()))
