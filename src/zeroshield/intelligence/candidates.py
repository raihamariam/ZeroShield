"""Domain classification and ValidationCandidate generation (Step 9).

Classification is deterministic keyword/vendor matching against an explicit,
adjustable list (_VPN_KEYWORDS/_TELECOM_KEYWORDS below) - not a model, not a
guess dressed up as fact. It is intentionally conservative: a strong
vendor+product combination match is SUPPORTED; a single ambiguous keyword hit
is PARTIALLY_SUPPORTED; no match at all is UNSUPPORTED. V2 full validation
support is VPN and Telecom only (zeroshield.strategies.registry already has
baseline+mitigation strategies for both - see zeroshield.strategies.vpn/telecom) -
this module never claims support for a domain with no installed validation pack.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from zeroshield.intelligence.priority import DEFAULT_WEIGHTS, PriorityWeights, score
from zeroshield.models.enums import Domain
from zeroshield.models.vulnerability import SupportStatus, ValidationCandidate, Vulnerability

# Adjustable, deterministic, explainable classification vocabulary - Step 9's
# "SUPPORTED/PARTIALLY_SUPPORTED/UNSUPPORTED" is derived only from this list,
# matched case-insensitively against vendor + product/description text.
VPN_STRONG_TERMS = {"vpn", "ssl-vpn", "ssl vpn", "ipsec"}
VPN_PRODUCT_TERMS = {
    "fortios", "forticlient", "pulse secure", "ivanti connect secure", "ivanti policy secure",
    "globalprotect", "anyconnect", "openvpn", "wireguard", "pptp", "l2tp", "sonicwall",
}
TELECOM_STRONG_TERMS = {"telecom", "telecommunications", "baseband", "cellular"}
TELECOM_PRODUCT_TERMS = {
    "sip", "diameter", "gtp", "volte", "ims", "3gpp", "ss7", "asterisk", "freeswitch",
    "modem", "rcs", "radio access", "ios xe",
}


@dataclass(frozen=True)
class DomainClassification:
    domain: Domain | None
    support_status: SupportStatus
    matched_terms: list[str]


def classify_domain(vulnerability: Vulnerability) -> DomainClassification:
    text = " ".join(
        filter(None, [vulnerability.vendor, vulnerability.description, *vulnerability.cwe_ids])
    ).lower()

    vpn_strong = sorted(t for t in VPN_STRONG_TERMS if t in text)
    vpn_product = sorted(t for t in VPN_PRODUCT_TERMS if t in text)
    telecom_strong = sorted(t for t in TELECOM_STRONG_TERMS if t in text)
    telecom_product = sorted(t for t in TELECOM_PRODUCT_TERMS if t in text)

    vpn_hits = vpn_strong + vpn_product
    telecom_hits = telecom_strong + telecom_product

    if vpn_hits and telecom_hits:
        # Ambiguous cross-domain match (e.g. a carrier-grade VPN concentrator) -
        # visible, but not confidently attributable to one runnable pack.
        return DomainClassification(None, SupportStatus.PARTIALLY_SUPPORTED, vpn_hits + telecom_hits)

    # A specific named product (e.g. "fortios", "openvpn") is a strong,
    # confident signal -> SUPPORTED. A merely generic term ("vpn", "ipsec")
    # with no specific product match is ambiguous -> PARTIALLY_SUPPORTED only -
    # the presence of a `vendor` field alone must never upgrade a generic term
    # to SUPPORTED (nearly every Vulnerability has a vendor).
    if vpn_product:
        return DomainClassification(Domain.VPN, SupportStatus.SUPPORTED, vpn_hits)
    if vpn_strong:
        return DomainClassification(Domain.VPN, SupportStatus.PARTIALLY_SUPPORTED, vpn_hits)

    if telecom_product:
        return DomainClassification(Domain.TELECOM, SupportStatus.SUPPORTED, telecom_hits)
    if telecom_strong:
        return DomainClassification(Domain.TELECOM, SupportStatus.PARTIALLY_SUPPORTED, telecom_hits)

    return DomainClassification(None, SupportStatus.UNSUPPORTED, [])


def generate_candidate(
    vulnerability: Vulnerability,
    *,
    experiment_ids_by_cve: Mapping[str, list[str]],
    weights: PriorityWeights = DEFAULT_WEIGHTS,
    clock: object = None,
) -> ValidationCandidate | None:
    """Returns a ValidationCandidate only when support_status is SUPPORTED or
    PARTIALLY_SUPPORTED (Step 9: "Generate ValidationCandidate records only
    where installed validation capabilities plausibly apply") - None for
    UNSUPPORTED, even though the Vulnerability record itself still exists and
    remains visible via GET /vulnerabilities.

    experiment_ids_by_cve maps cve_id -> the experiment_id(s) of any
    ExperimentDefinition already citing it in related_cves (see
    zeroshield.intelligence.sync_service, built from
    zeroshield.experiments.discovery) - existing_experiment_ids on the
    returned candidate, and "no existing validation coverage" in the priority
    explanation, both derive from this.
    """
    classification = classify_domain(vulnerability)
    if classification.support_status is SupportStatus.UNSUPPORTED:
        return None

    matching_experiment_ids = experiment_ids_by_cve.get(vulnerability.cve_id, [])
    result = score(
        vulnerability,
        support_status=classification.support_status,
        has_existing_validation_coverage=bool(matching_experiment_ids),
        weights=weights,
    )
    now = clock() if callable(clock) else datetime.now(UTC)

    return ValidationCandidate(
        cve_id=vulnerability.cve_id,
        domain=classification.domain,
        support_status=classification.support_status,
        priority_score=result.score,
        priority_label=result.label,
        explanation=result.explanation,
        existing_experiment_ids=matching_experiment_ids,
        generated_at=now,
    )
