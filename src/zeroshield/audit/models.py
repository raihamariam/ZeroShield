from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_id: str
    occurred_at: datetime
    actor_user_id: str | None = None
    actor_username: str | None = None
    actor_role: str | None = None
    action: str
    target_type: str | None = None
    target_id: str | None = None
    request_id: str | None = None
    metadata: dict[str, Any] = {}
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any] | None = None


class Action:
    """String constants, not an enum - mirrors
    zeroshield.assurance.models.RevalidationTrigger's reasoning: a new audit
    action must never require a migration, `action` is a plain indexed
    string column. Grouped to match Step 3's own list."""

    # -- security / session --------------------------------------------------
    LOGIN_SUCCESS = "auth.login_success"
    LOGIN_FAILURE = "auth.login_failure"
    LOGOUT = "auth.logout"
    ACCOUNT_LOCKED = "auth.account_locked"

    # -- users / roles --------------------------------------------------------
    USER_CREATED = "user.created"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_DEACTIVATED = "user.deactivated"
    USER_REACTIVATED = "user.reactivated"

    # -- experiment version / approval -----------------------------------------
    EXPERIMENT_VERSION_CREATED = "experiment_version.created"
    EXPERIMENT_VERSION_EDITED = "experiment_version.edited"
    EXPERIMENT_VERSION_SUBMITTED_FOR_REVIEW = "experiment_version.submitted_for_review"
    EXPERIMENT_VERSION_REVIEW_STARTED = "experiment_version.review_started"
    EXPERIMENT_VERSION_APPROVED = "experiment_version.approved"
    EXPERIMENT_VERSION_REJECTED = "experiment_version.rejected"
    EXPERIMENT_VERSION_RETIRED = "experiment_version.retired"
    EXPERIMENT_VERSION_SELF_APPROVAL_BLOCKED = "experiment_version.self_approval_blocked"

    # -- runs -------------------------------------------------------------------
    RUN_SUBMITTED = "run.submitted"
    RUN_DENIED = "run.denied"
    RUN_FAILED = "run.failed"

    # -- evidence -----------------------------------------------------------------
    EVIDENCE_CREATED = "evidence.created"
    EVIDENCE_VERIFIED = "evidence.verified"

    # -- intelligence -------------------------------------------------------------
    SYNC_INITIATED = "intelligence.sync_initiated"

    # -- configuration --------------------------------------------------------------
    CONFIG_CHANGED = "config.changed"

    # -- AI assessment review -------------------------------------------------------
    AI_ASSESSMENT_REVIEWED = "ai_assessment.reviewed"

    # -- assets / controls / revalidation --------------------------------------------
    ASSET_CREATED = "asset.created"
    ASSET_UPDATED = "asset.updated"
    REVALIDATION_CANDIDATE_APPROVED = "revalidation_candidate.approved"
    REVALIDATION_CANDIDATE_DISMISSED = "revalidation_candidate.dismissed"
