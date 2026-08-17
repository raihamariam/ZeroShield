"""Pydantic domain models for auth (V2 Phase 6, Step 1-2).

Mirrors zeroshield.assurance.models structurally: small, explicit Pydantic
models the repository converts ORM rows to/from - never the ORM classes
themselves crossing into service/route code.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Role(str, Enum):
    """Step 2's four roles, in ascending-privilege order for readability only
    (there is no automatic hierarchy in code - every route names the exact
    roles it allows, never "at least X"). See docs/V2_SECURITY.md for the
    full permission matrix."""

    VIEWER = "viewer"
    RESEARCHER = "researcher"
    REVIEWER = "reviewer"
    ADMIN = "admin"


class User(BaseModel):
    """Never carries password_hash - that field exists only on UserORM and
    inside zeroshield.auth.repository, so it can never accidentally leak
    into an API response or a log line via this model."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str = Field(min_length=1)
    role: Role
    active: bool = True
    created_at: datetime
    updated_at: datetime


class UserWithCredentials(User):
    """Only used inside zeroshield.auth - the one place a password hash is
    ever handled. Never returned from an API route or passed to logging/audit
    code (see zeroshield.auth.service for the boundary)."""

    password_hash: str
    failed_login_attempts: int = 0
    locked_until: datetime | None = None


class SessionRecord(BaseModel):
    """`session_id` here is always the SHA-256 hex digest of the raw cookie
    token, never the raw token itself - so a database read (backup, dump,
    replica) can never yield a usable session credential; only the original
    Set-Cookie response (issued once, at login) carries the raw value."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None
