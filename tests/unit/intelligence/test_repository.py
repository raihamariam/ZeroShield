"""Exercises VulnerabilityRepository against the in-memory SQLite fixture
(conftest.py's vuln_repo) - the same portable-SQLAlchemy pattern as
tests/unit/repositories/test_run_repository.py from Phase 1.
"""

from datetime import UTC, datetime

from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.models.enums import Domain
from zeroshield.models.vulnerability import (
    IntelligenceSync,
    IntelligenceSyncStatus,
    PriorityLabel,
    SupportStatus,
    ValidationCandidate,
    VendorAdvisory,
    Vulnerability,
    VulnerabilityHistoryEntry,
    VulnerabilitySourceName,
    VulnerabilitySourceRecord,
)

NOW = datetime.now(UTC)


def _vuln(**overrides: object) -> Vulnerability:
    base = {"cve_id": "CVE-2024-21762", "first_seen_at": NOW, "last_updated_at": NOW}
    base.update(overrides)
    return Vulnerability(**base)


def test_upsert_and_get_vulnerability_round_trips(vuln_repo: VulnerabilityRepository) -> None:
    v = _vuln(cvss_score=9.6, vendor="fortinet", domain_guess=Domain.VPN, sources=[VulnerabilitySourceName.NVD])
    vuln_repo.upsert_vulnerability(v)
    fetched = vuln_repo.get_vulnerability("CVE-2024-21762")
    assert fetched is not None
    assert fetched.cvss_score == 9.6
    assert fetched.domain_guess is Domain.VPN
    assert fetched.sources == [VulnerabilitySourceName.NVD]


def test_get_unknown_vulnerability_returns_none(vuln_repo: VulnerabilityRepository) -> None:
    assert vuln_repo.get_vulnerability("CVE-9999-99999") is None


def test_upsert_vulnerability_updates_existing_row(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln(cvss_score=5.0))
    vuln_repo.upsert_vulnerability(_vuln(cvss_score=9.6))
    assert vuln_repo.get_vulnerability("CVE-2024-21762").cvss_score == 9.6


def test_list_vulnerabilities_filters_by_kev_and_cvss(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln(cve_id="CVE-2024-00001", cvss_score=9.6, kev_listed=True))
    vuln_repo.upsert_vulnerability(_vuln(cve_id="CVE-2024-00002", cvss_score=3.0, kev_listed=False))

    kev_only, total = vuln_repo.list_vulnerabilities(kev=True)
    assert total == 1
    assert kev_only[0].cve_id == "CVE-2024-00001"

    high_cvss, total2 = vuln_repo.list_vulnerabilities(cvss_gte=5.0)
    assert total2 == 1
    assert high_cvss[0].cve_id == "CVE-2024-00001"


def test_list_vulnerabilities_paginates(vuln_repo: VulnerabilityRepository) -> None:
    for i in range(5):
        vuln_repo.upsert_vulnerability(_vuln(cve_id=f"CVE-2024-{10000 + i}"))
    page1, total = vuln_repo.list_vulnerabilities(limit=2, offset=0)
    page2, _ = vuln_repo.list_vulnerabilities(limit=2, offset=2)
    assert total == 5
    assert len(page1) == 2
    assert len(page2) == 2
    assert {v.cve_id for v in page1}.isdisjoint({v.cve_id for v in page2})


def test_source_record_upsert_and_get(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln())
    record = VulnerabilitySourceRecord(
        cve_id="CVE-2024-21762", source=VulnerabilitySourceName.NVD, cvss_score=9.6,
        first_seen_at=NOW, last_seen_at=NOW,
    )
    vuln_repo.upsert_source_record(record)
    sources = vuln_repo.get_sources("CVE-2024-21762")
    assert len(sources) == 1
    assert sources[0].cvss_score == 9.6

    # upserting the same (cve_id, source) again updates, not duplicates
    vuln_repo.upsert_source_record(record.model_copy(update={"cvss_score": 8.0}))
    sources_again = vuln_repo.get_sources("CVE-2024-21762")
    assert len(sources_again) == 1
    assert sources_again[0].cvss_score == 8.0


def test_append_history_and_get_history_ordered(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln())
    t1 = datetime(2024, 1, 1, tzinfo=UTC)
    t2 = datetime(2024, 6, 1, tzinfo=UTC)
    vuln_repo.append_history(
        [
            VulnerabilityHistoryEntry(
                cve_id="CVE-2024-21762", source=VulnerabilitySourceName.EPSS, field="epss_score",
                old_value=None, new_value="0.5", observed_at=t2,
            ),
            VulnerabilityHistoryEntry(
                cve_id="CVE-2024-21762", source=VulnerabilitySourceName.NVD, field="cvss_score",
                old_value=None, new_value="9.6", observed_at=t1,
            ),
        ]
    )
    history = vuln_repo.get_history("CVE-2024-21762")
    assert [h.field for h in history] == ["cvss_score", "epss_score"]  # ordered by observed_at


def test_get_vulnerability_as_of_reconstructs_point_in_time(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln())
    t1 = datetime(2024, 1, 1, tzinfo=UTC)
    t2 = datetime(2024, 6, 1, tzinfo=UTC)
    vuln_repo.append_history(
        [
            VulnerabilityHistoryEntry(
                cve_id="CVE-2024-21762", source=VulnerabilitySourceName.NVD, field="cvss_score",
                old_value=None, new_value="5.0", observed_at=t1,
            ),
            VulnerabilityHistoryEntry(
                cve_id="CVE-2024-21762", source=VulnerabilitySourceName.NVD, field="cvss_score",
                old_value="5.0", new_value="9.6", observed_at=t2,
            ),
        ]
    )
    as_of_before = vuln_repo.get_vulnerability_as_of("CVE-2024-21762", datetime(2024, 3, 1, tzinfo=UTC))
    as_of_after = vuln_repo.get_vulnerability_as_of("CVE-2024-21762", datetime(2024, 12, 1, tzinfo=UTC))
    assert as_of_before["cvss_score"] == "5.0"
    assert as_of_after["cvss_score"] == "9.6"


def test_get_vulnerability_as_of_before_any_history_is_none(vuln_repo: VulnerabilityRepository) -> None:
    assert vuln_repo.get_vulnerability_as_of("CVE-9999-99999", datetime(2020, 1, 1, tzinfo=UTC)) is None


def test_products_upsert_deduplicates_product_rows(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln())
    vuln_repo.upsert_products("CVE-2024-21762", [("fortinet", "fortios", ">=7.0.0")])
    vuln_repo.upsert_products("CVE-2024-21762", [("fortinet", "fortios", ">=7.0.1")])  # same product, new range
    _matches, total = vuln_repo.list_vulnerabilities(product="fortios")
    assert total == 1  # not 2 - upsert_products must not create a duplicate affected_products row


def test_vendor_advisory_upsert_and_list_by_cve_filter(vuln_repo: VulnerabilityRepository) -> None:
    advisory = VendorAdvisory(
        advisory_id="GHSA-xxxx", source=VulnerabilitySourceName.GITHUB_ADVISORY, cve_id="CVE-2024-21762",
        title="t", references=[],
    )
    vuln_repo.upsert_vendor_advisory(advisory)  # must not raise


def test_get_advisories_for_cve_returns_persisted_advisories(vuln_repo: VulnerabilityRepository) -> None:
    """Retrieval counterpart to upsert_vendor_advisory - advisories are
    written by intelligence sync but were previously unreadable by anything,
    including the AI mitigation-gap analyst."""
    vuln_repo.upsert_vendor_advisory(
        VendorAdvisory(
            advisory_id="GHSA-1", source=VulnerabilitySourceName.GITHUB_ADVISORY, cve_id="CVE-2024-21762",
            title="Advisory one", summary="Patch to 9.1", references=["https://example.com/a"],
        )
    )
    vuln_repo.upsert_vendor_advisory(
        VendorAdvisory(
            advisory_id="GHSA-2", source=VulnerabilitySourceName.GITHUB_ADVISORY, cve_id="CVE-2024-00099",
            title="Unrelated advisory", references=[],
        )
    )
    advisories = vuln_repo.get_advisories_for_cve("CVE-2024-21762")
    assert [a.advisory_id for a in advisories] == ["GHSA-1"]
    assert advisories[0].summary == "Patch to 9.1"
    assert advisories[0].references == ["https://example.com/a"]


def test_get_advisories_for_cve_with_no_advisories_returns_empty_list(vuln_repo: VulnerabilityRepository) -> None:
    assert vuln_repo.get_advisories_for_cve("CVE-2024-99999") == []


def test_validation_candidate_upsert_and_priority_queue(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln())
    vuln_repo.upsert_validation_candidate(
        ValidationCandidate(
            cve_id="CVE-2024-21762", domain=Domain.VPN, support_status=SupportStatus.SUPPORTED,
            priority_score=91.0, priority_label=PriorityLabel.CRITICAL, explanation=["x"], generated_at=NOW,
        )
    )
    candidates, total = vuln_repo.list_priority_queue()
    assert total == 1
    assert candidates[0].priority_score == 91.0

    _filtered, total2 = vuln_repo.list_priority_queue(support_status=SupportStatus.UNSUPPORTED)
    assert total2 == 0


def test_validation_candidate_upsert_updates_not_duplicates(vuln_repo: VulnerabilityRepository) -> None:
    vuln_repo.upsert_vulnerability(_vuln())
    for score_val in (50.0, 91.0):
        vuln_repo.upsert_validation_candidate(
            ValidationCandidate(
                cve_id="CVE-2024-21762", domain=Domain.VPN, support_status=SupportStatus.SUPPORTED,
                priority_score=score_val, priority_label=PriorityLabel.HIGH, explanation=["x"], generated_at=NOW,
            )
        )
    _, total = vuln_repo.list_priority_queue()
    assert total == 1


def test_sync_save_get_list(vuln_repo: VulnerabilityRepository) -> None:
    sync = IntelligenceSync(
        sync_id="SYNC-1", source=VulnerabilitySourceName.NVD, status=IntelligenceSyncStatus.COMPLETED,
        started_at=NOW, completed_at=NOW, fetched_count=10, created_count=5,
    )
    vuln_repo.save_sync(sync)
    fetched = vuln_repo.get_sync("SYNC-1")
    assert fetched.status is IntelligenceSyncStatus.COMPLETED
    assert fetched.fetched_count == 10
    assert len(vuln_repo.list_syncs()) == 1


def test_get_unknown_sync_returns_none(vuln_repo: VulnerabilityRepository) -> None:
    assert vuln_repo.get_sync("SYNC-does-not-exist") is None
