"""Control / control-version / control-effectiveness / regression routes
(V2 Phase 5, Steps 8/9/10). Thin wrappers - all aggregation and regression
logic lives in zeroshield.assurance.effectiveness/regression, never here.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from zeroshield.ai.provider import AIResponseError, AIUnavailableError
from zeroshield.ai.research_analyst_service import ResearchAnalystService
from zeroshield.api.dependencies import get_assurance_repository, get_research_analyst_service
from zeroshield.api.schemas import (
    AIAssessmentResponse,
    ControlEffectivenessResponse,
    ControlListResponse,
    ControlResponse,
    ControlValidationResponse,
    ControlVersionListResponse,
    ControlVersionResponse,
    RegressionResultResponse,
)
from zeroshield.assurance.effectiveness import summarise_effectiveness
from zeroshield.assurance.models import (
    AIAssessmentRecord,
    Control,
    ControlValidation,
    ControlVersion,
)
from zeroshield.assurance.regression import detect_regressions
from zeroshield.assurance.repository import AssuranceRepository

router = APIRouter(tags=["controls"])


def _control_response(c: Control) -> ControlResponse:
    return ControlResponse(
        control_id=c.control_id, name=c.name, domain=c.domain, mitigation_strategy_id=c.mitigation_strategy_id,
        created_at=c.created_at.isoformat(),
    )


def _version_response(v: ControlVersion) -> ControlVersionResponse:
    return ControlVersionResponse(
        version_id=v.version_id, control_id=v.control_id, version_label=v.version_label,
        domain_pack_id=v.domain_pack_id, template_id=v.template_id, template_version=v.template_version,
        created_at=v.created_at.isoformat(),
    )


def _validation_response(v: ControlValidation) -> ControlValidationResponse:
    return ControlValidationResponse(
        validation_id=v.validation_id, control_id=v.control_id, version_id=v.version_id,
        experiment_id=v.experiment_id, baseline_run_id=v.baseline_run_id, mitigation_run_id=v.mitigation_run_id,
        total_cases=v.total_cases, block_rate_improvement=v.block_rate_improvement,
        false_positive_rate=v.false_positive_rate, false_negative_rate=v.false_negative_rate,
        valid_acceptance_rate=v.valid_acceptance_rate, parser_reach_rate=v.parser_reach_rate,
        latency_overhead_ms=v.latency_overhead_ms, verdict_label=v.verdict_label,
        validated_at=v.validated_at.isoformat(),
    )


@router.get("/controls", response_model=ControlListResponse, summary="List defensive controls with validation history")
def list_controls(repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]) -> ControlListResponse:
    return ControlListResponse(controls=[_control_response(c) for c in repository.list_controls()])


@router.get("/controls/{control_id}", response_model=ControlResponse, summary="Get one control")
def get_control(
    control_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]
) -> ControlResponse:
    control = repository.get_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail={"error": "control_not_found", "detail": f"no control '{control_id}'"})
    return _control_response(control)


@router.get(
    "/controls/{control_id}/versions", response_model=ControlVersionListResponse, summary="List a control's versions"
)
def list_control_versions(
    control_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]
) -> ControlVersionListResponse:
    return ControlVersionListResponse(versions=[_version_response(v) for v in repository.list_control_versions(control_id)])


@router.get(
    "/controls/{control_id}/effectiveness",
    response_model=ControlEffectivenessResponse,
    summary="Control effectiveness: current state, trend, and regression status",
    description="Step 9: aggregates only within the current control version - never blends "
    "validations across versions. Step 10: also runs the deterministic regression rules "
    "against the two most recent validations, if there are at least two.",
)
def get_control_effectiveness(
    control_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]
) -> ControlEffectivenessResponse:
    control = repository.get_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail={"error": "control_not_found", "detail": f"no control '{control_id}'"})

    validations = repository.list_validations(control_id)
    summary = summarise_effectiveness(control_id, validations)
    if summary is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_validations", "detail": f"control '{control_id}' has no recorded validations yet"},
        )

    # Step 10 must honour Step 9's comparability rule: only compare two
    # validations of the *same* control version. A version bump (different
    # domain_pack/template/template_version) is a different thing being
    # measured, not a regression of the old one.
    regression = None
    current_version_validations = [v for v in validations if v.version_id == validations[-1].version_id]
    if len(current_version_validations) >= 2:
        result = detect_regressions(current_version_validations[-2], current_version_validations[-1])
        regression = RegressionResultResponse(
            is_regression=result.is_regression, reasons=result.reasons, thresholds_used=result.thresholds_used
        )

    return ControlEffectivenessResponse(
        control_id=summary.control_id, current_version_id=summary.current_version_id,
        current_version_label=summary.current_version_label,
        validation_count_current_version=summary.validation_count_current_version,
        total_validation_count=summary.total_validation_count,
        mean_block_rate_improvement_current_version=summary.mean_block_rate_improvement_current_version,
        latest_verdict=summary.latest_verdict, previous_verdict=summary.previous_verdict,
        last_validated_at=summary.last_validated_at.isoformat() if summary.last_validated_at else None,
        trend=[_validation_response(v) for v in summary.trend], comparability_note=summary.comparability_note,
        regression=regression,
    )


def _assessment_response(record: AIAssessmentRecord) -> AIAssessmentResponse:
    return AIAssessmentResponse(
        assessment_id=record.assessment_id, assessment_type=record.assessment_type,
        subject_type=record.subject_type, subject_id=record.subject_id, payload=record.payload,
        confidence=record.confidence, reviewed=record.reviewed, reviewed_by=record.reviewed_by,
        reviewed_at=record.reviewed_at.isoformat() if record.reviewed_at else None,
        review_note=record.review_note, created_at=record.created_at.isoformat(),
    )


@router.post(
    "/controls/{control_id}/regression/explain",
    response_model=AIAssessmentResponse,
    status_code=201,
    summary="AI: explain an already-detected regression (advisory)",
    description="Step 10: 'AI may explain a regression, not independently declare it.' Recomputes "
    "the same deterministic detect_regressions() result GET .../effectiveness returns, and only "
    "calls the AI if is_regression is already true - the AI is handed the final reasons list and "
    "narrates it, it never re-decides whether a regression occurred.",
)
def explain_regression(
    control_id: str,
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    analyst: Annotated[ResearchAnalystService, Depends(get_research_analyst_service)],
) -> AIAssessmentResponse:
    control = repository.get_control(control_id)
    if control is None:
        raise HTTPException(status_code=404, detail={"error": "control_not_found", "detail": f"no control '{control_id}'"})

    validations = repository.list_validations(control_id)
    if not validations:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_validations", "detail": f"control '{control_id}' has no recorded validations yet"},
        )
    current_version_validations = [v for v in validations if v.version_id == validations[-1].version_id]
    if len(current_version_validations) < 2:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "no_regression",
                "detail": f"control '{control_id}' does not have two validations on its current version to compare",
            },
        )
    result = detect_regressions(current_version_validations[-2], current_version_validations[-1])
    if not result.is_regression:
        raise HTTPException(
            status_code=404, detail={"error": "no_regression", "detail": f"control '{control_id}' is not currently regressed"}
        )

    try:
        assessment = analyst.explain_regression(control_id=control_id, reasons=result.reasons)
    except AIUnavailableError as exc:
        raise HTTPException(status_code=503, detail={"error": "ai_unavailable", "detail": str(exc)}) from None
    except AIResponseError as exc:
        raise HTTPException(status_code=502, detail={"error": "ai_response_invalid", "detail": str(exc)}) from None

    record = repository.save_assessment(
        assessment_type="regression_explanation", subject_type="control", subject_id=control_id,
        payload=assessment.model_dump(mode="json"), confidence=assessment.confidence,
    )
    return _assessment_response(record)
