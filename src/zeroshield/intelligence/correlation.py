"""CVE correlation/similarity engine (V2 Phase 5, Step 4).

Deterministic and fully explainable, in the same spirit as
zeroshield.intelligence.priority: every point of similarity is a named,
weighted, structured feature - no learned model, no embeddings, no hidden
weighting. pgvector/semantic embeddings were deliberately NOT added: the
phase brief says to add pgvector "only if semantic retrieval provides clear
value; do not add it for decoration," and structured-feature + text-overlap
similarity already gives a real, useful, zero-new-infrastructure signal.
`text_similarity` below is the one "semantic-ish" signal here, and it is
plain difflib token-ratio over descriptions - genuinely just text overlap,
not an embedding, and never claimed to be one.

Similarity is never proof of identical root cause (Step 4: "must not be
presented as proof") - CorrelationResult.explanation always states exactly
which features matched and by how much, so a reviewer can judge for
themselves rather than trust a single opaque score.
"""

import difflib
from dataclasses import dataclass, field

from zeroshield.models.vulnerability import Vulnerability


@dataclass(frozen=True)
class CorrelationWeights:
    """Every weight is a maximum contribution; mirrors
    zeroshield.intelligence.priority.PriorityWeights as the one adjustable
    configuration point for retuning."""

    cwe_overlap_max: float = 25.0
    vendor_match_flat: float = 15.0
    domain_match_flat: float = 10.0
    trust_boundary_match_flat: float = 10.0
    text_similarity_max: float = 20.0
    shared_experiment_flat: float = 20.0

    def total_max(self) -> float:
        return (
            self.cwe_overlap_max
            + self.vendor_match_flat
            + self.domain_match_flat
            + self.trust_boundary_match_flat
            + self.text_similarity_max
            + self.shared_experiment_flat
        )


DEFAULT_WEIGHTS = CorrelationWeights()

CAVEAT = "Similarity is a structured/textual signal, not proof of identical root cause."


@dataclass(frozen=True)
class CorrelationResult:
    cve_id: str
    score: float
    explanation: list[str] = field(default_factory=list)
    shared_experiment_ids: list[str] = field(default_factory=list)


def _cwe_overlap(a: list[str], b: list[str], weights: CorrelationWeights) -> tuple[float, str]:
    set_a, set_b = set(a), set(b)
    if not set_a or not set_b:
        return 0.0, f"No CWE data to compare on one or both sides: +0.0/{weights.cwe_overlap_max:.1f}"
    overlap = set_a & set_b
    jaccard = len(overlap) / len(set_a | set_b)
    points = jaccard * weights.cwe_overlap_max
    return points, f"CWE overlap {sorted(overlap) or '(none)'} (Jaccard {jaccard:.2f}): +{points:.1f}/{weights.cwe_overlap_max:.1f}"


def _text_similarity(a: str | None, b: str | None, weights: CorrelationWeights) -> tuple[float, str]:
    if not a or not b:
        return 0.0, f"No description to compare on one or both sides: +0.0/{weights.text_similarity_max:.1f}"
    ratio = difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()
    points = ratio * weights.text_similarity_max
    return points, f"Description text similarity {ratio:.2f}: +{points:.1f}/{weights.text_similarity_max:.1f}"


def correlate(
    subject: Vulnerability,
    candidate: Vulnerability,
    *,
    subject_experiment_ids: list[str] | None = None,
    candidate_experiment_ids: list[str] | None = None,
    weights: CorrelationWeights = DEFAULT_WEIGHTS,
) -> CorrelationResult:
    """Scores `candidate`'s similarity to `subject`. Symmetric in every
    feature except the caller-supplied experiment-ID lists, so callers
    should pass consistent inputs both directions if they need a symmetric
    score."""
    explanation: list[str] = []
    total = 0.0

    cwe_points, cwe_reason = _cwe_overlap(subject.cwe_ids, candidate.cwe_ids, weights)
    total += cwe_points
    explanation.append(cwe_reason)

    if subject.vendor and candidate.vendor and subject.vendor.strip().lower() == candidate.vendor.strip().lower():
        total += weights.vendor_match_flat
        explanation.append(f"Same vendor ({subject.vendor}): +{weights.vendor_match_flat:.1f}")
    else:
        explanation.append(f"Different or unknown vendor: +0.0/{weights.vendor_match_flat:.1f}")

    if subject.domain_guess is not None and subject.domain_guess == candidate.domain_guess:
        total += weights.domain_match_flat
        explanation.append(f"Same domain ({subject.domain_guess.value}): +{weights.domain_match_flat:.1f}")
    else:
        explanation.append(f"Different or unknown domain: +0.0/{weights.domain_match_flat:.1f}")

    if (
        subject.zero_click_relevance is not None
        and candidate.zero_click_relevance is not None
        and subject.zero_click_relevance == candidate.zero_click_relevance
    ):
        total += weights.trust_boundary_match_flat
        explanation.append(
            f"Same zero-interaction/pre-auth relevance ({subject.zero_click_relevance.value}): "
            f"+{weights.trust_boundary_match_flat:.1f}"
        )
    else:
        explanation.append(f"Zero-interaction/pre-auth relevance differs or unknown: +0.0/{weights.trust_boundary_match_flat:.1f}")

    text_points, text_reason = _text_similarity(subject.description, candidate.description, weights)
    total += text_points
    explanation.append(text_reason)

    shared = sorted(set(subject_experiment_ids or []) & set(candidate_experiment_ids or []))
    if shared:
        total += weights.shared_experiment_flat
        explanation.append(f"Already linked to a shared experiment {shared}: +{weights.shared_experiment_flat:.1f}")
    else:
        explanation.append(f"No shared experiment coverage: +0.0/{weights.shared_experiment_flat:.1f}")

    total = min(total, weights.total_max())
    explanation.append(f"Total: {total:.1f}/{weights.total_max():.0f}. {CAVEAT}")

    return CorrelationResult(
        cve_id=candidate.cve_id, score=round(total, 1), explanation=explanation, shared_experiment_ids=shared
    )


def rank_correlations(
    subject: Vulnerability,
    candidates: list[Vulnerability],
    *,
    subject_experiment_ids: list[str] | None = None,
    candidate_experiment_ids: dict[str, list[str]] | None = None,
    weights: CorrelationWeights = DEFAULT_WEIGHTS,
    min_score: float = 0.0,
    limit: int = 10,
) -> list[CorrelationResult]:
    """Scores every candidate against `subject` (excluding `subject` itself
    by cve_id) and returns the top `limit`, highest score first."""
    candidate_experiment_ids = candidate_experiment_ids or {}
    results = [
        correlate(
            subject,
            candidate,
            subject_experiment_ids=subject_experiment_ids,
            candidate_experiment_ids=candidate_experiment_ids.get(candidate.cve_id),
            weights=weights,
        )
        for candidate in candidates
        if candidate.cve_id != subject.cve_id
    ]
    results = [r for r in results if r.score >= min_score]
    results.sort(key=lambda r: r.score, reverse=True)
    return results[:limit]
