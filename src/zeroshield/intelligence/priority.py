"""ZeroShield Validation Priority engine (Step 8).

Explicitly NOT an industry-standard risk score (not CVSS, not a CVSS/EPSS
average) - a deterministic, fully explainable 0-100 value expressing how
worth-validating a CVE is to ZeroShield specifically, given what it can
actually run. No AI, no learned model, no hidden weighting: every input and
its exact contribution is listed in PriorityResult.explanation.

Weights (PriorityWeights) sum to 100 by construction and are the one place
that would need editing to retune scoring - "Configuration must be explicit
and adjustable" (Step 8). Domain relevance is itself modulated by
zero-click/pre-authentication relevance when known (Step 8: "established
zero-interaction/pre-auth relevance"), since raw NVD/KEV/EPSS data never
states this directly - see _domain_points.
"""

from dataclasses import dataclass

from zeroshield.models.enums import ZeroClickRelevance
from zeroshield.models.vulnerability import PriorityLabel, SupportStatus, Vulnerability


@dataclass(frozen=True)
class PriorityWeights:
    """Every weight is a maximum contribution; the four categories sum to 100.
    Pass a custom instance to score()/explain() to retune without code changes
    elsewhere - this is the single adjustable configuration point Step 8 asks for."""

    cvss_max: float = 30.0
    epss_max: float = 25.0
    kev_flat: float = 20.0
    domain_max: float = 15.0
    no_coverage_flat: float = 10.0

    def total_max(self) -> float:
        return self.cvss_max + self.epss_max + self.kev_flat + self.domain_max + self.no_coverage_flat


DEFAULT_WEIGHTS = PriorityWeights()

_CRITICAL_THRESHOLD = 85.0
_HIGH_THRESHOLD = 65.0
_MEDIUM_THRESHOLD = 40.0


@dataclass(frozen=True)
class PriorityResult:
    score: float
    label: PriorityLabel
    explanation: list[str]


def label_for_score(score: float) -> PriorityLabel:
    if score >= _CRITICAL_THRESHOLD:
        return PriorityLabel.CRITICAL
    if score >= _HIGH_THRESHOLD:
        return PriorityLabel.HIGH
    if score >= _MEDIUM_THRESHOLD:
        return PriorityLabel.MEDIUM
    return PriorityLabel.LOW


def _domain_points(
    support_status: SupportStatus, zero_click: ZeroClickRelevance | None, weights: PriorityWeights
) -> tuple[float, str]:
    """Domain relevance is only worth its full weight when ZeroShield both
    (a) has a runnable validation pack for the domain AND (b) has reason to
    believe the CVE is genuinely zero-interaction/pre-auth-relevant. Unknown
    relevance (the common case for freshly-ingested NVD/KEV/EPSS data, which
    never states this) gets half credit rather than none or full - a
    deliberate, documented middle ground, not a guess presented as fact."""
    if support_status is SupportStatus.UNSUPPORTED:
        return 0.0, "Domain is UNSUPPORTED (no installed validation pack applies): +0.0"
    base = weights.domain_max if support_status is SupportStatus.SUPPORTED else weights.domain_max / 2
    status_label = support_status.value.upper()

    if zero_click is ZeroClickRelevance.HIGH:
        points = base
        reason = f"Domain is {status_label} and zero-interaction relevance is HIGH"
    elif zero_click is ZeroClickRelevance.MEDIUM:
        points = base * 0.5
        reason = f"Domain is {status_label} and zero-interaction relevance is MEDIUM"
    elif zero_click is ZeroClickRelevance.LOW:
        points = 0.0
        reason = f"Domain is {status_label} but zero-interaction relevance is LOW"
    else:
        points = base * 0.5
        reason = f"Domain is {status_label}; zero-interaction relevance unknown (no bonus/penalty applied)"

    return points, f"{reason}: +{points:.1f}/{weights.domain_max:.1f}"


def score(
    vulnerability: Vulnerability,
    *,
    support_status: SupportStatus,
    has_existing_validation_coverage: bool,
    weights: PriorityWeights = DEFAULT_WEIGHTS,
) -> PriorityResult:
    """Computes the ZeroShield Validation Priority and a human-readable
    explanation for every point awarded - Step 8: "Every score must explain
    why it was produced." `has_existing_validation_coverage` is whether any
    ExperimentDefinition already references this cve_id (see
    zeroshield.intelligence.candidates), independent of approval status."""
    explanation: list[str] = []
    total = 0.0

    if vulnerability.cvss_score is not None:
        points = (vulnerability.cvss_score / 10.0) * weights.cvss_max
        total += points
        explanation.append(
            f"CVSS {vulnerability.cvss_score:.1f}/10 contributes {points:.1f}/{weights.cvss_max:.1f}"
        )
    else:
        explanation.append(f"No CVSS score available: +0.0/{weights.cvss_max:.1f}")

    if vulnerability.epss_score is not None:
        points = vulnerability.epss_score * weights.epss_max
        total += points
        explanation.append(
            f"EPSS {vulnerability.epss_score:.3f} contributes {points:.1f}/{weights.epss_max:.1f}"
        )
    else:
        explanation.append(f"No EPSS score available: +0.0/{weights.epss_max:.1f}")

    if vulnerability.kev_listed:
        total += weights.kev_flat
        explanation.append(f"Listed in CISA KEV: +{weights.kev_flat:.1f}")
    else:
        explanation.append("Not listed in CISA KEV: +0.0")

    domain_points, domain_reason = _domain_points(support_status, vulnerability.zero_click_relevance, weights)
    total += domain_points
    explanation.append(domain_reason)

    if not has_existing_validation_coverage:
        total += weights.no_coverage_flat
        explanation.append(f"No existing validation coverage for this CVE: +{weights.no_coverage_flat:.1f}")
    else:
        explanation.append("Already covered by an existing experiment: +0.0")

    total = min(total, weights.total_max())
    label = label_for_score(total)
    explanation.append(f"Total: {total:.1f}/{weights.total_max():.0f} -> {label.value.upper()}")

    return PriorityResult(score=round(total, 1), label=label, explanation=explanation)
