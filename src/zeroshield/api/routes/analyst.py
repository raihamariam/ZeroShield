"""ZeroShield AI Research Analyst routes (V2 Phase 5, Steps 2/5/6).

Every handler here: resolves real context from the existing repositories/
registries (never lets the AI invent it), calls zeroshield.ai.
research_analyst_service.ResearchAnalystService, persists the result as an
AIAssessmentRecord with reviewed=False, and returns it. AIUnavailableError
(AI disabled/misconfigured) maps to 503 - the rest of the API, and every
other route in this file's siblings, works identically whether or not AI is
configured (Step 1). AIResponseError (the provider answered but the answer
couldn't be trusted) maps to 502, since the fault is the upstream
provider's, not the client's request.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from zeroshield.ai.provider import AIResponseError, AIUnavailableError
from zeroshield.ai.research_analyst_service import ResearchAnalystService
from zeroshield.ai.schemas import AIAssessmentBase
from zeroshield.api.dependencies import (
    CurrentUser,
    get_assurance_repository,
    get_audit_repository,
    get_experiments_dir,
    get_request_id,
    get_research_analyst_service,
    get_vulnerability_repository,
    require_role,
)
from zeroshield.api.schemas import (
    AIAssessmentListResponse,
    AIAssessmentResponse,
    CorrelatedVulnerabilityResponse,
    CorrelationListResponse,
    ExperimentDraftRequest,
    ReviewAssessmentRequest,
)
from zeroshield.assurance.models import AIAssessmentRecord
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.audit.models import Action
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role, User
from zeroshield.domain_packs import UnknownDomainPackError, resolve_domain_pack
from zeroshield.intelligence.correlation import rank_correlations
from zeroshield.intelligence.repository import VulnerabilityRepository
from zeroshield.intelligence.sync_service import build_experiment_ids_by_cve
from zeroshield.models.vulnerability import Vulnerability
from zeroshield.templates import list_templates

_ANALYST_ROLES = (Role.RESEARCHER, Role.REVIEWER, Role.ADMIN)

router = APIRouter(tags=["analyst"])


def _assessment_response(record: AIAssessmentRecord) -> AIAssessmentResponse:
    return AIAssessmentResponse(
        assessment_id=record.assessment_id, assessment_type=record.assessment_type,
        subject_type=record.subject_type, subject_id=record.subject_id, payload=record.payload,
        confidence=record.confidence, reviewed=record.reviewed, reviewed_by=record.reviewed_by,
        reviewed_at=record.reviewed_at.isoformat() if record.reviewed_at else None,
        review_note=record.review_note, created_at=record.created_at.isoformat(),
    )


def _get_vulnerability(cve_id: str, vuln_repository: VulnerabilityRepository) -> Vulnerability:
    vulnerability = vuln_repository.get_vulnerability(cve_id)
    if vulnerability is None:
        raise HTTPException(
            status_code=404, detail={"error": "vulnerability_not_found", "detail": f"no vulnerability '{cve_id}'"}
        )
    return vulnerability


def _save(
    assurance_repository: AssuranceRepository, *, assessment_type: str, subject_id: str, payload_model: AIAssessmentBase
) -> AIAssessmentResponse:
    record = assurance_repository.save_assessment(
        assessment_type=assessment_type, subject_type="vulnerability", subject_id=subject_id,
        payload=payload_model.model_dump(mode="json"), confidence=payload_model.confidence,
    )
    return _assessment_response(record)


def _ai_call[T: AIAssessmentBase](fn: Callable[[], T]) -> T:
    try:
        return fn()
    except AIUnavailableError as exc:
        raise HTTPException(status_code=503, detail={"error": "ai_unavailable", "detail": str(exc)}) from None
    except AIResponseError as exc:
        raise HTTPException(status_code=502, detail={"error": "ai_response_invalid", "detail": str(exc)}) from None


@router.post(
    "/vulnerabilities/{cve_id}/analyst/failure-pattern",
    response_model=AIAssessmentResponse,
    status_code=201,
    summary="AI: classify the defensive failure pattern (advisory)",
)
def classify_failure_pattern(
    cve_id: str,
    vuln_repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    assurance_repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    analyst: Annotated[ResearchAnalystService, Depends(get_research_analyst_service)],
    _current_user: Annotated[User, Depends(require_role(*_ANALYST_ROLES))],
) -> AIAssessmentResponse:
    vulnerability = _get_vulnerability(cve_id, vuln_repository)
    candidates: list[str] = []
    if vulnerability.domain_guess is not None:
        try:
            pack = resolve_domain_pack(vulnerability.domain_guess.value.lower())
            candidates = list(pack.supported_failure_patterns)
        except UnknownDomainPackError:
            pass

    assessment = _ai_call(
        lambda: analyst.classify_failure_pattern(
            cve_id=cve_id, description=vulnerability.description, cvss_score=vulnerability.cvss_score,
            epss_score=vulnerability.epss_score, kev_listed=vulnerability.kev_listed,
            domain_hint=vulnerability.domain_guess.value if vulnerability.domain_guess else None,
            candidate_failure_patterns=candidates,
        )
    )
    return _save(assurance_repository, assessment_type="failure_pattern", subject_id=cve_id, payload_model=assessment)


@router.post(
    "/vulnerabilities/{cve_id}/analyst/mitigation-gap",
    response_model=AIAssessmentResponse,
    status_code=201,
    summary="AI: identify mitigation gaps (advisory)",
)
def analyze_mitigation_gap(
    cve_id: str,
    vuln_repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    assurance_repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    analyst: Annotated[ResearchAnalystService, Depends(get_research_analyst_service)],
    _current_user: Annotated[User, Depends(require_role(*_ANALYST_ROLES))],
) -> AIAssessmentResponse:
    vulnerability = _get_vulnerability(cve_id, vuln_repository)
    # Ground the analysis in real, retrieved vendor advisory text (Step 3) rather
    # than always handing the AI nothing to work from - advisories are persisted
    # by intelligence sync but were previously unreadable by anything.
    advisories = vuln_repository.get_advisories_for_cve(cve_id)
    vendor_mitigation = (
        "\n\n".join(f"[{a.advisory_id}] {a.title}: {a.summary or '(no summary)'}" for a in advisories)
        if advisories
        else None
    )
    assessment = _ai_call(
        lambda: analyst.analyze_mitigation_gap(
            cve_id=cve_id, description=vulnerability.description, vendor_mitigation=vendor_mitigation
        )
    )
    return _save(assurance_repository, assessment_type="mitigation_gap", subject_id=cve_id, payload_model=assessment)


@router.get(
    "/vulnerabilities/{cve_id}/correlations",
    response_model=CorrelationListResponse,
    summary="Deterministic CVE correlation/similarity (Step 4)",
    description="No AI - structured features only (CWE overlap, vendor/product match, domain, "
    "text similarity, shared experiment coverage). Never proof of identical root cause.",
)
def get_correlations(
    cve_id: str,
    vuln_repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
    _current_user: CurrentUser,
) -> CorrelationListResponse:
    subject = _get_vulnerability(cve_id, vuln_repository)
    candidates, _total = vuln_repository.list_vulnerabilities(domain=subject.domain_guess, limit=200)
    experiment_ids_by_cve = build_experiment_ids_by_cve(experiments_dir)
    results = rank_correlations(
        subject, candidates, min_score=20.0, limit=10,
        subject_experiment_ids=experiment_ids_by_cve.get(cve_id, []),
        candidate_experiment_ids=experiment_ids_by_cve,
    )
    return CorrelationListResponse(
        cve_id=cve_id,
        correlations=[
            CorrelatedVulnerabilityResponse(
                cve_id=r.cve_id, score=r.score, explanation=r.explanation, shared_experiment_ids=r.shared_experiment_ids
            )
            for r in results
        ],
        caveat="Similarity is a structured/textual signal, not proof of identical root cause.",
    )


@router.post(
    "/vulnerabilities/{cve_id}/analyst/similar",
    response_model=AIAssessmentResponse,
    status_code=201,
    summary="AI: narrate the deterministic correlation results (advisory)",
    description="Never asked to find similar CVEs itself - only to explain a candidate list "
    "already produced by GET .../correlations.",
)
def summarise_similarity(
    cve_id: str,
    vuln_repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    assurance_repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    analyst: Annotated[ResearchAnalystService, Depends(get_research_analyst_service)],
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
    _current_user: Annotated[User, Depends(require_role(*_ANALYST_ROLES))],
) -> AIAssessmentResponse:
    subject = _get_vulnerability(cve_id, vuln_repository)
    candidates, _total = vuln_repository.list_vulnerabilities(domain=subject.domain_guess, limit=200)
    experiment_ids_by_cve = build_experiment_ids_by_cve(experiments_dir)
    correlations = rank_correlations(
        subject, candidates, min_score=20.0, limit=10,
        subject_experiment_ids=experiment_ids_by_cve.get(cve_id, []),
        candidate_experiment_ids=experiment_ids_by_cve,
    )
    if not correlations:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_correlations", "detail": f"no correlated CVEs found for '{cve_id}' to summarise"},
        )
    notes = "\n".join(f"{r.cve_id}: {'; '.join(r.explanation)}" for r in correlations)
    assessment = _ai_call(
        lambda: analyst.summarise_similarity(
            cve_id=cve_id, candidate_cve_ids=[r.cve_id for r in correlations], correlation_notes=notes
        )
    )
    return _save(assurance_repository, assessment_type="similarity", subject_id=cve_id, payload_model=assessment)


@router.post(
    "/vulnerabilities/{cve_id}/analyst/template-recommendation",
    response_model=AIAssessmentResponse,
    status_code=201,
    summary="AI: recommend an existing allow-listed validation template (advisory)",
    description="Step 6: the AI selects from real, already-registered templates in the CVE's "
    "domain - it can never invent one, enforced by ResearchAnalystService.",
)
def recommend_template(
    cve_id: str,
    vuln_repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    assurance_repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    analyst: Annotated[ResearchAnalystService, Depends(get_research_analyst_service)],
    _current_user: Annotated[User, Depends(require_role(*_ANALYST_ROLES))],
) -> AIAssessmentResponse:
    vulnerability = _get_vulnerability(cve_id, vuln_repository)
    if vulnerability.domain_guess is None:
        raise HTTPException(
            status_code=422,
            detail={"error": "unsupported_domain", "detail": f"'{cve_id}' has no determined domain to match templates against"},
        )
    domain_pack_id = vulnerability.domain_guess.value.lower()
    try:
        resolve_domain_pack(domain_pack_id)
    except UnknownDomainPackError:
        raise HTTPException(
            status_code=422,
            detail={"error": "unsupported_domain", "detail": f"no domain pack registered for '{domain_pack_id}'"},
        ) from None

    candidates = [(domain_pack_id, t.template_id, t.version) for t in list_templates(domain_pack_id)]
    latest_failure_pattern = next(
        (
            a.payload.get("failure_pattern")
            for a in assurance_repository.list_assessments(
                subject_type="vulnerability", subject_id=cve_id, assessment_type="failure_pattern"
            )
        ),
        None,
    )

    assessment = _ai_call(
        lambda: analyst.recommend_template(
            cve_id=cve_id, failure_pattern=latest_failure_pattern, description=vulnerability.description,
            candidates=candidates,
        )
    )
    return _save(assurance_repository, assessment_type="template_recommendation", subject_id=cve_id, payload_model=assessment)


@router.post(
    "/vulnerabilities/{cve_id}/analyst/experiment-draft",
    response_model=AIAssessmentResponse,
    status_code=201,
    summary="AI: draft a starting-point experiment proposal (advisory)",
    description="Purely advisory text for a human to copy into Experiment Studio - this endpoint "
    "cannot create an experiment version itself.",
)
def draft_experiment_proposal(
    cve_id: str,
    request: ExperimentDraftRequest,
    vuln_repository: Annotated[VulnerabilityRepository, Depends(get_vulnerability_repository)],
    assurance_repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    analyst: Annotated[ResearchAnalystService, Depends(get_research_analyst_service)],
    _current_user: Annotated[User, Depends(require_role(*_ANALYST_ROLES))],
) -> AIAssessmentResponse:
    vulnerability = _get_vulnerability(cve_id, vuln_repository)
    try:
        resolve_domain_pack(request.domain_pack_id)
    except UnknownDomainPackError:
        raise HTTPException(
            status_code=422,
            detail={"error": "unsupported_domain", "detail": f"no domain pack registered for '{request.domain_pack_id}'"},
        ) from None
    known_template_ids = {t.template_id for t in list_templates(request.domain_pack_id)}
    if request.template_id not in known_template_ids:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unknown_template",
                "detail": f"'{request.template_id}' is not a registered template for domain pack "
                f"'{request.domain_pack_id}'; known templates: {sorted(known_template_ids)}",
            },
        )

    latest_failure_pattern = next(
        (
            a.payload.get("failure_pattern")
            for a in assurance_repository.list_assessments(
                subject_type="vulnerability", subject_id=cve_id, assessment_type="failure_pattern"
            )
        ),
        None,
    )
    assessment = _ai_call(
        lambda: analyst.draft_experiment_proposal(
            cve_id=cve_id, description=vulnerability.description, failure_pattern=latest_failure_pattern,
            domain_pack_id=request.domain_pack_id, template_id=request.template_id,
        )
    )
    return _save(assurance_repository, assessment_type="experiment_draft", subject_id=cve_id, payload_model=assessment)


@router.get("/ai-assessments", response_model=AIAssessmentListResponse, summary="List persisted AI assessments")
def list_assessments(
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    _current_user: CurrentUser,
    subject_type: str | None = None,
    subject_id: str | None = None,
    assessment_type: str | None = None,
    reviewed: bool | None = None,
) -> AIAssessmentListResponse:
    records = repository.list_assessments(
        subject_type=subject_type, subject_id=subject_id, assessment_type=assessment_type, reviewed=reviewed
    )
    return AIAssessmentListResponse(assessments=[_assessment_response(r) for r in records])


@router.get("/ai-assessments/{assessment_id}", response_model=AIAssessmentResponse, summary="Get one AI assessment")
def get_assessment(
    assessment_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    _current_user: CurrentUser,
) -> AIAssessmentResponse:
    record = repository.get_assessment(assessment_id)
    if record is None:
        raise HTTPException(
            status_code=404, detail={"error": "assessment_not_found", "detail": f"no assessment '{assessment_id}'"}
        )
    return _assessment_response(record)


@router.post(
    "/ai-assessments/{assessment_id}/review",
    response_model=AIAssessmentResponse,
    summary="Mark an AI assessment reviewed",
    description="Step 2: AI output is untrusted advisory data until a human explicitly reviews "
    "it - this is that action. Never automatic, never inferred from any other event.",
)
def review_assessment(
    assessment_id: str,
    request: ReviewAssessmentRequest,
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    audit_repository: Annotated[AuditRepository, Depends(get_audit_repository)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    current_user: Annotated[User, Depends(require_role(*_ANALYST_ROLES))],
) -> AIAssessmentResponse:
    record = repository.mark_assessment_reviewed(
        assessment_id, reviewed_by=current_user.username, review_note=request.note
    )
    if record is None:
        raise HTTPException(
            status_code=404, detail={"error": "assessment_not_found", "detail": f"no assessment '{assessment_id}'"}
        )
    audit_repository.record(
        actor_user_id=current_user.user_id, actor_username=current_user.username, actor_role=current_user.role.value,
        action=Action.AI_ASSESSMENT_REVIEWED, target_type="ai_assessment", target_id=assessment_id,
        request_id=request_id, metadata={"assessment_type": record.assessment_type},
    )
    return _assessment_response(record)
