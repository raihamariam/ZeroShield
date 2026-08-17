"""Maps each connector's RawIntelligenceRecord to one common shape (Step 4).

Deliberately a plain dataclass, not a Pydantic model with a CveId/score-range
constraints: normalisation is "best-effort structural mapping from raw JSON",
lenient about malformed individual fields (they become None here); the actual
"treat external data as untrusted" validation gate is
zeroshield.intelligence.dedup, which builds Pydantic
VulnerabilitySourceRecord/Vulnerability instances from a NormalisedContribution
and lets pydantic's own validation (CveId pattern, 0-10/0-1 score ranges)
reject genuinely bad data - counted as a failed record by
zeroshield.intelligence.sync_service, never silently persisted or fatal to
the whole sync.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from zeroshield.intelligence.connectors.base import RawIntelligenceRecord
from zeroshield.models.enums import ZeroClickRelevance
from zeroshield.models.vulnerability import VendorAdvisory, VulnerabilitySourceName

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_URL_RE = re.compile(r"https?://[^\s)\]]+")


class NormalisationError(Exception):
    def __init__(self, source: VulnerabilitySourceName, external_id: str, reason: str) -> None:
        super().__init__(f"[{source.value}:{external_id}] {reason}")
        self.source = source
        self.external_id = external_id
        self.reason = reason


@dataclass(frozen=True)
class NormalisedContribution:
    cve_id: str
    source: VulnerabilitySourceName
    source_identifier: str | None
    description: str | None
    published_at: datetime | None
    last_modified_at: datetime | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    epss_score: float | None
    epss_percentile: float | None
    epss_date: date | None
    kev_listed: bool | None
    kev_date_added: date | None
    kev_due_date: date | None
    kev_known_ransomware: str | None
    cwe_ids: list[str] = field(default_factory=list)
    vendor: str | None = None
    products: list[tuple[str, str, str | None]] = field(default_factory=list)  # (vendor, product, version_range)
    references: list[str] = field(default_factory=list)
    zero_click_relevance: ZeroClickRelevance | None = None


def normalise(record: RawIntelligenceRecord) -> NormalisedContribution:
    """Dispatches to the source-specific mapper. Raises NormalisationError if
    the record has no usable CVE ID at all (nothing downstream can be built
    without one) - every other missing/malformed field just becomes None."""
    if record.source is VulnerabilitySourceName.NVD:
        return _normalise_nvd(record)
    if record.source is VulnerabilitySourceName.CISA_KEV:
        return _normalise_cisa_kev(record)
    if record.source is VulnerabilitySourceName.EPSS:
        return _normalise_epss(record)
    raise NormalisationError(
        record.source, record.external_id, f"no normaliser registered for source {record.source.value}"
    )


def _require_cve_id(record: RawIntelligenceRecord, candidate: str | None) -> str:
    if not candidate or not _CVE_ID_RE.match(candidate):
        raise NormalisationError(
            record.source, record.external_id, f"missing or malformed CVE ID: {candidate!r}"
        )
    return candidate


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        text = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _parse_date(value: object) -> date | None:
    dt = _parse_datetime(value) if isinstance(value, str) and "T" in value else None
    if dt is not None:
        return dt.date()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _normalise_nvd(record: RawIntelligenceRecord) -> NormalisedContribution:
    raw = record.raw
    cve_id = _require_cve_id(record, raw.get("id"))

    description = None
    for desc in raw.get("descriptions") or []:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            description = desc.get("value")
            break

    cvss_score = cvss_vector = cvss_version = None
    raw_metrics = raw.get("metrics")
    metrics: dict[str, Any] = raw_metrics if isinstance(raw_metrics, dict) else {}
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            data = entries[0].get("cvssData") if isinstance(entries[0], dict) else None
            if isinstance(data, dict):
                cvss_score = data.get("baseScore")
                cvss_vector = data.get("vectorString")
                cvss_version = version
                break

    cwe_ids: list[str] = []
    for weakness in raw.get("weaknesses") or []:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description") or []:
            if isinstance(desc, dict) and isinstance(desc.get("value"), str):
                cwe_ids.append(desc["value"])

    references = [
        ref["url"]
        for ref in (raw.get("references") or [])
        if isinstance(ref, dict) and isinstance(ref.get("url"), str)
    ]

    vendor, products = _extract_nvd_products(raw)

    return NormalisedContribution(
        cve_id=cve_id,
        source=record.source,
        source_identifier=raw.get("sourceIdentifier"),
        description=description,
        published_at=_parse_datetime(raw.get("published")),
        last_modified_at=_parse_datetime(raw.get("lastModified")),
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cvss_version=cvss_version,
        epss_score=None,
        epss_percentile=None,
        epss_date=None,
        kev_listed=None,
        kev_date_added=None,
        kev_due_date=None,
        kev_known_ransomware=None,
        cwe_ids=cwe_ids,
        vendor=vendor,
        products=products,
        references=references,
    )


def _extract_nvd_products(raw: dict[str, Any]) -> tuple[str | None, list[tuple[str, str, str | None]]]:
    """Best-effort extraction from NVD's CPE `configurations[]` match nodes -
    takes the first CPE URI per node (cpe:2.3:a:vendor:product:version:...),
    with any versionStart/versionEnd range as a human-readable string. Does
    NOT model the full boolean AND/OR/NEGATE operator tree NVD's
    configurations can express - a documented simplification (see the Phase 2
    Completion Report), sufficient for a best-effort vendor/product/version hint."""
    products: list[tuple[str, str, str | None]] = []
    vendor: str | None = None
    for config in raw.get("configurations") or []:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable", True):
                    continue
                cpe_uri = match.get("criteria")
                if not isinstance(cpe_uri, str):
                    continue
                parts = cpe_uri.split(":")
                if len(parts) < 6:
                    continue
                cpe_vendor, cpe_product = parts[3], parts[4]
                version_range = _cpe_version_range(match)
                products.append((cpe_vendor, cpe_product, version_range))
                vendor = vendor or cpe_vendor
    return vendor, products


def _cpe_version_range(match: dict[str, Any]) -> str | None:
    bounds = []
    for key, label in (
        ("versionStartIncluding", ">="),
        ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="),
        ("versionEndExcluding", "<"),
    ):
        if match.get(key):
            bounds.append(f"{label}{match[key]}")
    return " ".join(bounds) if bounds else None


def _normalise_cisa_kev(record: RawIntelligenceRecord) -> NormalisedContribution:
    raw = record.raw
    cve_id = _require_cve_id(record, raw.get("cveID"))
    raw_vendor, raw_product = raw.get("vendorProject"), raw.get("product")
    vendor = raw_vendor if isinstance(raw_vendor, str) else None
    product = raw_product if isinstance(raw_product, str) else None
    products: list[tuple[str, str, str | None]] = [(vendor, product, None)] if vendor and product else []
    references = _URL_RE.findall(raw.get("notes") or "")

    return NormalisedContribution(
        cve_id=cve_id,
        source=record.source,
        source_identifier=None,
        description=raw.get("shortDescription") if isinstance(raw.get("shortDescription"), str) else None,
        published_at=None,
        last_modified_at=None,
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        epss_score=None,
        epss_percentile=None,
        epss_date=None,
        kev_listed=True,
        kev_date_added=_parse_date(raw.get("dateAdded")),
        kev_due_date=_parse_date(raw.get("dueDate")),
        kev_known_ransomware=raw.get("knownRansomwareCampaignUse")
        if isinstance(raw.get("knownRansomwareCampaignUse"), str)
        else None,
        cwe_ids=[c for c in (raw.get("cwes") or []) if isinstance(c, str)],
        vendor=vendor,
        products=products,
        references=references,
    )


def _normalise_epss(record: RawIntelligenceRecord) -> NormalisedContribution:
    raw = record.raw
    cve_id = _require_cve_id(record, raw.get("cve"))

    def _to_float(value: object) -> float | None:
        if not isinstance(value, str | int | float):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    return NormalisedContribution(
        cve_id=cve_id,
        source=record.source,
        source_identifier=None,
        description=None,
        published_at=None,
        last_modified_at=None,
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        epss_score=_to_float(raw.get("epss")),
        epss_percentile=_to_float(raw.get("percentile")),
        epss_date=_parse_date(raw.get("date")),
        kev_listed=None,
        kev_date_added=None,
        kev_due_date=None,
        kev_known_ransomware=None,
    )


def normalise_vendor_advisory(
    record: RawIntelligenceRecord,
) -> tuple[VendorAdvisory, NormalisedContribution | None]:
    """GitHub Advisories only, for now - see VendorAdvisoryConnector's contract:
    `raw["cve_id"]` links the advisory to a Vulnerability when present. Always
    returns a VendorAdvisory (persisted regardless); the NormalisedContribution
    is None when the advisory has no linked CVE ID."""
    if record.source is not VulnerabilitySourceName.GITHUB_ADVISORY:
        raise NormalisationError(
            record.source, record.external_id, "not a recognised vendor advisory source"
        )
    raw = record.raw
    advisory_id = record.external_id or "UNKNOWN"

    cvss = None
    raw_severities = raw.get("cvss_severities")
    severities: dict[str, Any] = raw_severities if isinstance(raw_severities, dict) else {}
    for key in ("cvss_v4", "cvss_v3"):
        entry = severities.get(key)
        if isinstance(entry, dict) and entry.get("score") is not None:
            cvss = entry
            break
    if cvss is None and isinstance(raw.get("cvss"), dict):
        cvss = raw["cvss"]

    references = [r for r in (raw.get("references") or []) if isinstance(r, str)]

    advisory = VendorAdvisory(
        advisory_id=advisory_id,
        source=record.source,
        cve_id=raw.get("cve_id") if isinstance(raw.get("cve_id"), str) and _CVE_ID_RE.match(raw.get("cve_id", "")) else None,
        title=raw.get("summary") or advisory_id,
        summary=raw.get("description") if isinstance(raw.get("description"), str) else None,
        severity=raw.get("severity") if isinstance(raw.get("severity"), str) else None,
        published_at=_parse_datetime(raw.get("published_at")),
        updated_at=_parse_datetime(raw.get("updated_at")),
        references=references,
    )

    cve_id_raw = raw.get("cve_id")
    if not isinstance(cve_id_raw, str) or not _CVE_ID_RE.match(cve_id_raw):
        return advisory, None

    cwe_ids = [
        c.get("cwe_id") for c in (raw.get("cwes") or []) if isinstance(c, dict) and isinstance(c.get("cwe_id"), str)
    ]

    contribution = NormalisedContribution(
        cve_id=cve_id_raw,
        source=record.source,
        source_identifier=advisory_id,
        description=raw.get("summary") if isinstance(raw.get("summary"), str) else None,
        published_at=advisory.published_at,
        last_modified_at=advisory.updated_at,
        cvss_score=cvss.get("score") if isinstance(cvss, dict) else None,
        cvss_vector=cvss.get("vector_string") if isinstance(cvss, dict) else None,
        cvss_version="4.0" if cvss is severities.get("cvss_v4") else "3.1",
        epss_score=None,
        epss_percentile=None,
        epss_date=None,
        kev_listed=None,
        kev_date_added=None,
        kev_due_date=None,
        kev_known_ransomware=None,
        cwe_ids=[c for c in cwe_ids if c],
        references=references,
    )
    return advisory, contribution
