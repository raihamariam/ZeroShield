"""Pydantic domain models for the assurance package (V2 Phase 5, Steps 2/7/8/11).

Kept deliberately small - Step 7 explicitly asks for a "deliberately small"
asset inventory, not a full CMDB, and the same restraint applies to the
control/revalidation models: just enough fields to support the phase's
acceptance gate (correlation -> priority -> AI-assisted research -> template
recommendation -> human review -> validation -> evidence -> control
effectiveness -> change/regression -> revalidation candidate), nothing
speculative.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Asset(BaseModel):
    """Step 7: "asset ID/name, vendor, product, version, environment,
    exposure, criticality, active status" - exactly that list, no more."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    version: str | None = None
    environment: str = Field(min_length=1, description="e.g. production, staging, lab")
    exposure: str = Field(min_length=1, description="e.g. internet_facing, internal, isolated")
    criticality: str = Field(min_length=1, description="e.g. critical, high, medium, low")
    active: bool = True
    created_at: datetime
    updated_at: datetime


class Control(BaseModel):
    """A defensive control ZeroShield validates - identified by (domain,
    mitigation_strategy), since that pair is what "the control" actually
    means operationally: the specific mitigation code path being measured.
    See zeroshield.assurance.repository.control_id_for for the derivation."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    name: str
    domain: str
    mitigation_strategy_id: str
    created_at: datetime


class ControlVersion(BaseModel):
    """One version of a Control - keyed to the ExperimentDefinition.version
    that was validated (Studio-authored experiments increment this on every
    new version; hand-authored V1 experiments have exactly one, "1.0.0")."""

    model_config = ConfigDict(extra="forbid")

    version_id: str
    control_id: str
    version_label: str
    domain_pack_id: str
    template_id: str
    template_version: str
    created_at: datetime


class ControlValidation(BaseModel):
    """One immutable row per completed run against a control version (Step
    8: "Historical results remain immutable"). Written once, by the worker,
    right after a run completes - never updated or deleted."""

    model_config = ConfigDict(extra="forbid")

    validation_id: str
    control_id: str
    version_id: str
    experiment_id: str
    baseline_run_id: str
    mitigation_run_id: str
    total_cases: int
    block_rate_improvement: float
    false_positive_rate: float
    false_negative_rate: float
    valid_acceptance_rate: float
    parser_reach_rate: float
    latency_overhead_ms: float
    verdict_label: str
    validated_at: datetime


class RevalidationTrigger:
    """String constants, not an enum, so a new trigger type never requires
    a migration - trigger_type is a plain indexed string column."""

    NEW_RELATED_CVE = "new_related_cve"
    KEV_STATE_CHANGE = "kev_state_change"
    EPSS_MATERIAL_CHANGE = "epss_material_change"
    ADVISORY_UPDATE = "advisory_update"
    VERSION_CHANGE = "version_change"
    SCHEDULED = "scheduled"
    REGRESSION = "regression"


class RevalidationCandidate(BaseModel):
    """Step 11: trigger -> impacted control/experiment -> candidate ->
    human review/approval -> normal execution. This record IS the pause
    point - nothing in this codebase auto-executes a run from a candidate;
    `status` only ever moves pending -> approved/dismissed by a human
    action (zeroshield.api.routes.revalidation), and "approved" means
    "go run this through the normal Experiments/Runs UI," not "run it"."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    control_id: str
    experiment_id: str | None = None
    trigger_type: str
    trigger_detail: str
    status: str = "pending"
    created_at: datetime
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None


class AIAssessmentRecord(BaseModel):
    """Persisted wrapper around any zeroshield.ai.schemas.AIAssessmentBase
    subclass - `payload` is that schema's own model_dump(mode="json").
    `reviewed` starts False on every insert (Step 2: "treat outputs as
    untrusted advisory data until reviewed") and is only ever flipped by an
    explicit human review action, never automatically."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    assessment_type: str
    subject_type: str
    subject_id: str
    payload: dict[str, Any]
    confidence: float
    reviewed: bool = False
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None
    created_at: datetime
