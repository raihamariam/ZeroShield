"""Provider-neutral AI abstraction (V2 Phase 5, Step 1).

NON-NEGOTIABLE AI BOUNDARIES (V2 Improvement Plan, Phase 5):

AI MAY: explain CVEs, classify defensive failure patterns, summarise
advisories, identify mitigation gaps, find similar historical CVEs,
retrieve prior experiments, recommend EXISTING allow-listed templates,
draft experiment proposals, and summarise validation evidence.

AI MAY NEVER: approve experiments, change or bypass SafetyPolicy, modify
historical evidence, publish arbitrary execution jobs, execute generated
code, construct shell commands, create weaponised exploits, or silently
change a deterministic verdict.

This module is deliberately incapable of any of the "may never" list: it
exposes exactly one operation - "given a prompt and a JSON schema, return a
JSON object matching that schema, or fail" - with no tool use, no code
execution, and no access to any ZeroShield service that could execute a run,
approve a version, or write evidence. Every caller (zeroshield.ai.
research_analyst_service) treats the returned dict as untrusted advisory
data: it is validated against a Pydantic schema in zeroshield.ai.schemas and
persisted with a "reviewed=False" flag - nothing here is ever accepted as
fact without a subsequent human review action.

Core ZeroShield (experiment execution, SafetyPolicy, approvals, evidence)
never imports this package and has no dependency on any AIProvider - see
zeroshield.api.dependencies.get_research_analyst_service for the one place
AI is wired in, and its NullAIProvider fallback for what happens when AI is
disabled/misconfigured: every route stays fully functional, just answering
"AI is currently unavailable" instead of a assessment.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


class AIUnavailableError(Exception):
    """Raised when no AI provider is configured/reachable. Callers must
    treat this as an ordinary, expected condition (503-style), never as a
    reason to fail a request that doesn't strictly need AI."""


class AIResponseError(Exception):
    """Raised when the provider responded but its output could not be
    trusted as-is: invalid JSON, a schema mismatch, or a policy refusal.
    Never silently coerced into a best-effort guess."""


@dataclass(frozen=True)
class AIGenerationRequest:
    system: str
    prompt: str
    json_schema: dict[str, Any]
    schema_name: str
    max_tokens: int = 2000


@dataclass(frozen=True)
class AIGenerationResult:
    """Raw provider output plus the metadata every AI schema in
    zeroshield.ai.schemas requires (Step 2: "model/provider metadata and
    timestamp"). `data` is still untrusted - the caller validates it against
    the target Pydantic model before using it for anything."""

    data: dict[str, Any]
    provider: str
    model: str


class AIProvider(ABC):
    """One operation only: structured JSON generation. No tool use, no code
    execution, no filesystem/network access beyond calling the provider's
    own text-generation API - by construction, nothing implementing this
    interface can perform any action on the "AI may never" list above."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Cheap, non-network check - used to fail fast with AIUnavailableError
        before spending a request on a provider that was never set up."""

    @abstractmethod
    def generate_structured(self, request: AIGenerationRequest) -> AIGenerationResult:
        """Returns a JSON object matching request.json_schema. Raises
        AIUnavailableError if the provider cannot be reached at all, or
        AIResponseError if it responded but the output can't be trusted
        (invalid JSON, refusal, schema violation) - never returns a
        fabricated or partially-guessed result."""
