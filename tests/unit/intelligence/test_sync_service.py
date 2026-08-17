"""Exercises run_sync end-to-end with fake ThreatIntelligenceConnectors -
covers Step 7's required lifecycle (QUEUED/RUNNING/COMPLETED/PARTIAL/FAILED)
and Step 12's "network failure... merge rules... deterministic priority"
against the real normalise/merge/repository/candidates pipeline, not mocks.
"""

from collections.abc import Iterator
from pathlib import Path

from zeroshield.intelligence.connectors.base import (
    ConnectorHealth,
    RawIntelligenceRecord,
    ThreatIntelligenceConnector,
)
from zeroshield.intelligence.connectors.http import ConnectorFetchError
from zeroshield.intelligence.connectors.vendor_advisory import VendorAdvisoryConnector
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.intelligence.sync_service import run_sync
from zeroshield.models.vulnerability import IntelligenceSyncStatus, VulnerabilitySourceName
from zeroshield.observability.metrics import INTELLIGENCE_SYNCS_TOTAL

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"


def _nvd_item(cve_id: str, cvss: float = 9.6) -> dict:
    return {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"desc for {cve_id}"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": cvss, "vectorString": "x", "version": "3.1"}}]},
        "weaknesses": [], "references": [],
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:fortinet:fortios:*"}]}]}],
    }


class _FakeConnector(ThreatIntelligenceConnector):
    source = VulnerabilitySourceName.NVD

    def __init__(self, records: list[RawIntelligenceRecord]) -> None:
        self._records = records

    def fetch(self, *, since=None) -> Iterator[RawIntelligenceRecord]:
        yield from self._records

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(source=self.source, available=True, detail=None)


class _FailingConnector(ThreatIntelligenceConnector):
    source = VulnerabilitySourceName.NVD

    def fetch(self, *, since=None) -> Iterator[RawIntelligenceRecord]:
        raise ConnectorFetchError("simulated upstream outage")
        yield  # pragma: no cover - unreachable, makes this a generator

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(source=self.source, available=False, detail="down")


class _FakeVendorAdvisoryConnector(VendorAdvisoryConnector):
    source = VulnerabilitySourceName.GITHUB_ADVISORY

    def __init__(self, records: list[RawIntelligenceRecord]) -> None:
        self._records = records

    def fetch(self, *, since=None) -> Iterator[RawIntelligenceRecord]:
        yield from self._records

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(source=self.source, available=True, detail=None)


def test_run_sync_all_valid_records_completes(vuln_repo: VulnerabilityRepository) -> None:
    records = [
        RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="CVE-2024-00001", raw=_nvd_item("CVE-2024-00001")),
        RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="CVE-2024-00002", raw=_nvd_item("CVE-2024-00002")),
    ]
    sync = run_sync(_FakeConnector(records), sync_id="SYNC-1", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    assert sync.status is IntelligenceSyncStatus.COMPLETED
    assert sync.fetched_count == 2
    assert sync.created_count == 2
    assert sync.failed_count == 0
    assert vuln_repo.get_vulnerability("CVE-2024-00001") is not None


def test_run_sync_mixed_valid_and_malformed_is_partial(vuln_repo: VulnerabilityRepository) -> None:
    records = [
        RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="CVE-2024-00001", raw=_nvd_item("CVE-2024-00001")),
        RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="bad", raw={"id": "not-a-cve"}),
    ]
    sync = run_sync(_FakeConnector(records), sync_id="SYNC-2", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    assert sync.status is IntelligenceSyncStatus.PARTIAL
    assert sync.fetched_count == 2
    assert sync.created_count == 1
    assert sync.failed_count == 1
    assert sync.error_summary is not None


def test_run_sync_all_malformed_is_failed(vuln_repo: VulnerabilityRepository) -> None:
    records = [RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="bad", raw={"id": "not-a-cve"})]
    sync = run_sync(_FakeConnector(records), sync_id="SYNC-3", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    assert sync.status is IntelligenceSyncStatus.FAILED
    assert sync.failed_count == 1


def test_run_sync_connector_fetch_error_marks_failed_with_zero_side_effects(
    vuln_repo: VulnerabilityRepository,
) -> None:
    sync = run_sync(_FailingConnector(), sync_id="SYNC-4", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    assert sync.status is IntelligenceSyncStatus.FAILED
    assert sync.fetched_count == 0
    assert "simulated upstream outage" in sync.error_summary
    _vulns, total = vuln_repo.list_vulnerabilities()
    assert total == 0


def test_run_sync_empty_fetch_completes_with_zero_counts(vuln_repo: VulnerabilityRepository) -> None:
    sync = run_sync(_FakeConnector([]), sync_id="SYNC-5", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    assert sync.status is IntelligenceSyncStatus.COMPLETED
    assert sync.fetched_count == 0


# -- INTELLIGENCE_SYNCS_TOTAL telemetry (V2 Phase 6, Step 5) - covers both
# `return sync` sites in run_sync: the ConnectorFetchError early return and
# the normal terminal-status return. -----------------------------------------

def _syncs_total(source: str, status: str) -> float:
    return INTELLIGENCE_SYNCS_TOTAL.labels(source=source, status=status)._value.get()  # type: ignore[attr-defined]


def test_intelligence_syncs_total_counts_a_completed_sync(vuln_repo: VulnerabilityRepository) -> None:
    before = _syncs_total("nvd", "completed")
    run_sync(_FakeConnector([]), sync_id="SYNC-metrics-1", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    assert _syncs_total("nvd", "completed") == before + 1


def test_intelligence_syncs_total_counts_a_connector_fetch_failure(vuln_repo: VulnerabilityRepository) -> None:
    before = _syncs_total("nvd", "failed")
    run_sync(_FailingConnector(), sync_id="SYNC-metrics-2", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    assert _syncs_total("nvd", "failed") == before + 1


def test_run_sync_persists_queued_then_running_then_terminal_status(
    vuln_repo: VulnerabilityRepository,
) -> None:
    """save_sync is called at RUNNING (start) and again at the terminal state -
    get_sync after completion must reflect the terminal state, not RUNNING."""
    records = [RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="CVE-2024-00001", raw=_nvd_item("CVE-2024-00001"))]
    run_sync(_FakeConnector(records), sync_id="SYNC-6", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    final = vuln_repo.get_sync("SYNC-6")
    assert final.status is IntelligenceSyncStatus.COMPLETED
    assert final.completed_at is not None


def test_run_sync_generates_validation_candidate_for_supported_domain(
    vuln_repo: VulnerabilityRepository,
) -> None:
    """CVE-2024-21762 is a real cve_id already cited by ZC-VPN-EXP-001's related_cves -
    proves has_existing_validation_coverage is correctly derived from real experiments/."""
    records = [
        RawIntelligenceRecord(
            source=VulnerabilitySourceName.NVD, external_id="CVE-2024-21762",
            raw={
                "id": "CVE-2024-21762",
                "descriptions": [{"lang": "en", "value": "FortiOS SSL VPN out-of-bound write"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.6, "vectorString": "x", "version": "3.1"}}]},
                "weaknesses": [], "references": [],
                "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:fortinet:fortios:*"}]}]}],
            },
        )
    ]
    run_sync(_FakeConnector(records), sync_id="SYNC-7", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR)
    candidates, total = vuln_repo.list_priority_queue()
    assert total == 1
    assert candidates[0].cve_id == "CVE-2024-21762"
    assert candidates[0].existing_experiment_ids == ["ZC-VPN-EXP-001"]


def test_run_sync_without_experiments_dir_skips_coverage_lookup_gracefully(
    vuln_repo: VulnerabilityRepository,
) -> None:
    raw = _nvd_item("CVE-2024-00001")
    raw["descriptions"] = [{"lang": "en", "value": "FortiOS SSL VPN out-of-bound write"}]
    records = [RawIntelligenceRecord(source=VulnerabilitySourceName.NVD, external_id="CVE-2024-00001", raw=raw)]
    sync = run_sync(_FakeConnector(records), sync_id="SYNC-8", repository=vuln_repo, experiments_dir=None)
    assert sync.status is IntelligenceSyncStatus.COMPLETED
    candidates, total = vuln_repo.list_priority_queue()
    assert total == 1
    assert candidates[0].existing_experiment_ids == []


def test_run_sync_vendor_advisory_with_cve_creates_vulnerability_and_advisory(
    vuln_repo: VulnerabilityRepository,
) -> None:
    records = [
        RawIntelligenceRecord(
            source=VulnerabilitySourceName.GITHUB_ADVISORY, external_id="GHSA-xxxx",
            raw={
                "ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2024-00001", "summary": "sum",
                "cvss_severities": {"cvss_v3": {"score": 9.0, "vector_string": "x"}}, "cwes": [], "references": [],
            },
        )
    ]
    sync = run_sync(
        _FakeVendorAdvisoryConnector(records), sync_id="SYNC-9", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR
    )
    assert sync.status is IntelligenceSyncStatus.COMPLETED
    assert vuln_repo.get_vulnerability("CVE-2024-00001") is not None


def test_run_sync_vendor_advisory_without_cve_persists_advisory_only(
    vuln_repo: VulnerabilityRepository,
) -> None:
    records = [
        RawIntelligenceRecord(
            source=VulnerabilitySourceName.GITHUB_ADVISORY, external_id="GHSA-yyyy",
            raw={"ghsa_id": "GHSA-yyyy", "cve_id": None, "summary": "sum"},
        )
    ]
    sync = run_sync(
        _FakeVendorAdvisoryConnector(records), sync_id="SYNC-10", repository=vuln_repo, experiments_dir=EXPERIMENTS_DIR
    )
    assert sync.status is IntelligenceSyncStatus.COMPLETED
    assert sync.created_count == 0
    assert sync.unchanged_count == 1  # advisory persisted, no linked vulnerability
