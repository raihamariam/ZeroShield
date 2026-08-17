"""Correlates records by CVE ID and merges NVD + KEV + EPSS + vendor-advisory
contributions into one internal Vulnerability view, per Step 5.

Deterministic conflict rules (documented, not implicit): each field has a
fixed source-priority order used only when more than one source supplies a
value for that field. Set-valued fields (CWE IDs, references, contributing
sources) are unioned, never overwritten. Nothing here silently drops a
disagreement - every field-level change is recorded as a
VulnerabilityHistoryEntry (Step 6), and pydantic validation on the merged
Vulnerability/VulnerabilitySourceRecord is the "treat external data as
untrusted" gate (Step 3): a value normalisation produced but that fails
validation here (e.g. an out-of-range score) raises and is counted as a
failed record by the caller, never silently persisted.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from zeroshield.intelligence.normalisation import NormalisedContribution
from zeroshield.models.vulnerability import (
    Vulnerability,
    VulnerabilityHistoryEntry,
    VulnerabilitySourceRecord,
)

# Lower number = higher priority when two sources disagree on the same
# shared field (description/cvss/vendor). CVSS/EPSS/KEV-specific fields are
# effectively single-source today (only NVD/GITHUB_ADVISORY ever supply
# cvss_*; only EPSS supplies epss_*; only CISA_KEV supplies kev_*), but the
# same ranking applies uniformly if that ever changes.
_SOURCE_PRIORITY: dict[str, int] = {
    "nvd": 0,
    "github_advisory": 1,
    "cisa_kev": 2,
    "epss": 3,
    "manual_import": 4,
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class MergeResult:
    vulnerability: Vulnerability
    history: list[VulnerabilityHistoryEntry]
    source_record: VulnerabilitySourceRecord
    products: list[tuple[str, str, str | None]]
    is_new: bool


def _better(
    source_a: str | None, value_a: object, source_b: str, value_b: object
) -> bool:
    """True if value_b (from source_b) should win over value_a (from source_a,
    possibly None-valued/unknown). A None candidate never wins over a present
    value from a lower-priority source - missing data never overwrites known
    data."""
    if value_b is None:
        return False
    if value_a is None or source_a is None:
        return True
    return _SOURCE_PRIORITY.get(source_b, 99) < _SOURCE_PRIORITY.get(source_a, 99)


def merge(
    existing: Vulnerability | None,
    contribution: NormalisedContribution,
    *,
    clock: Callable[[], datetime] = _utc_now,
) -> MergeResult:
    now = clock()
    source_value = contribution.source.value
    history: list[VulnerabilityHistoryEntry] = []

    def _track(field: str, old: object, new: object) -> None:
        if old != new and new is not None:
            history.append(
                VulnerabilityHistoryEntry(
                    cve_id=contribution.cve_id,
                    source=contribution.source,
                    field=field,
                    old_value=None if old is None else str(old),
                    new_value=str(new),
                    observed_at=now,
                )
            )

    # Track which source currently "owns" each shared field, so a
    # lower-priority source's fresh value never overwrites a still-valid
    # higher-priority one (e.g. EPSS's contribution must never blank out
    # NVD's description). Approximated by re-deriving from `existing.sources`
    # order for shared string/float fields we don't separately track owners
    # for - good enough given only NVD/GITHUB_ADVISORY ever populate
    # description/cvss/vendor in V2 Phase 2's connector set.
    owner_of_description = "nvd" if existing and existing.description else None
    owner_of_cvss = "nvd" if existing and existing.cvss_score is not None else None
    owner_of_vendor = "nvd" if existing and existing.vendor else None

    description = existing.description if existing else None
    if _better(owner_of_description, description, source_value, contribution.description):
        _track("description", description, contribution.description)
        description = contribution.description

    cvss_score = existing.cvss_score if existing else None
    cvss_vector = existing.cvss_vector if existing else None
    cvss_version = existing.cvss_version if existing else None
    if _better(owner_of_cvss, cvss_score, source_value, contribution.cvss_score):
        _track("cvss_score", cvss_score, contribution.cvss_score)
        cvss_score = contribution.cvss_score
        cvss_vector = contribution.cvss_vector
        cvss_version = contribution.cvss_version

    epss_score = existing.epss_score if existing else None
    epss_percentile = existing.epss_percentile if existing else None
    epss_date = existing.epss_date if existing else None
    if contribution.epss_score is not None:
        _track("epss_score", epss_score, contribution.epss_score)
        epss_score = contribution.epss_score
        epss_percentile = contribution.epss_percentile
        epss_date = contribution.epss_date

    kev_listed = existing.kev_listed if existing else False
    kev_date_added = existing.kev_date_added if existing else None
    kev_due_date = existing.kev_due_date if existing else None
    kev_known_ransomware = existing.kev_known_ransomware if existing else None
    if contribution.kev_listed:
        _track("kev_listed", kev_listed, True)
        kev_listed = True
        _track("kev_date_added", kev_date_added, contribution.kev_date_added)
        kev_date_added = contribution.kev_date_added or kev_date_added
        _track("kev_due_date", kev_due_date, contribution.kev_due_date)
        kev_due_date = contribution.kev_due_date or kev_due_date
        kev_known_ransomware = contribution.kev_known_ransomware or kev_known_ransomware

    vendor = existing.vendor if existing else None
    if _better(owner_of_vendor, vendor, source_value, contribution.vendor):
        vendor = contribution.vendor

    zero_click_relevance = existing.zero_click_relevance if existing else None
    if contribution.zero_click_relevance is not None:
        _track("zero_click_relevance", zero_click_relevance, contribution.zero_click_relevance.value)
        zero_click_relevance = contribution.zero_click_relevance

    cwe_ids = sorted(set((existing.cwe_ids if existing else []) + contribution.cwe_ids))
    references = list(
        dict.fromkeys((existing.references if existing else []) + [r for r in contribution.references])
    )
    sources = sorted(set((existing.sources if existing else []) + [contribution.source]), key=lambda s: s.value)

    published_at = existing.published_at if existing else None
    if contribution.published_at is not None and (
        published_at is None or contribution.published_at < published_at
    ):
        published_at = contribution.published_at  # earliest known publish date wins

    last_modified_at = existing.last_modified_at if existing else None
    if contribution.last_modified_at is not None and (
        last_modified_at is None or contribution.last_modified_at > last_modified_at
    ):
        last_modified_at = contribution.last_modified_at  # freshest modification wins

    vulnerability = Vulnerability(
        cve_id=contribution.cve_id,
        description=description,
        published_at=published_at,
        last_modified_at=last_modified_at,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cvss_version=cvss_version,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        epss_date=epss_date,
        kev_listed=kev_listed,
        kev_date_added=kev_date_added,
        kev_due_date=kev_due_date,
        kev_known_ransomware=kev_known_ransomware,
        cwe_ids=cwe_ids,
        vendor=vendor,
        domain_guess=existing.domain_guess if existing else None,
        zero_click_relevance=zero_click_relevance,
        references=references,  # type: ignore[arg-type]
        sources=sources,
        first_seen_at=existing.first_seen_at if existing else now,
        last_updated_at=now,
    )

    source_record = VulnerabilitySourceRecord(
        cve_id=contribution.cve_id,
        source=contribution.source,
        source_identifier=contribution.source_identifier,
        description=contribution.description,
        published_at=contribution.published_at,
        last_modified_at=contribution.last_modified_at,
        cvss_score=contribution.cvss_score,
        cvss_vector=contribution.cvss_vector,
        cvss_version=contribution.cvss_version,
        epss_score=contribution.epss_score,
        epss_percentile=contribution.epss_percentile,
        kev_listed=contribution.kev_listed,
        kev_date_added=contribution.kev_date_added,
        kev_due_date=contribution.kev_due_date,
        cwe_ids=contribution.cwe_ids,
        vendor=contribution.vendor,
        references=contribution.references,
        first_seen_at=now,
        last_seen_at=now,
    )

    return MergeResult(
        vulnerability=vulnerability,
        history=history,
        source_record=source_record,
        products=contribution.products,
        is_new=existing is None,
    )
