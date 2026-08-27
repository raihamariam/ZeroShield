"""Schema-validated AI output structures (V2 Phase 5, Step 2).

Every model here is what Step 2 requires: confidence, a concise rationale,
source IDs/references, model/provider metadata, and a generation timestamp.
`ai_output_schema()` derives the JSON Schema the AI is actually asked to
fill in - everything except `provider`/`model`/`generated_at`, which this
application stamps itself after the call returns (never trusting the model
to self-report its own identity or the current time). The AI's raw JSON is
validated against the full Pydantic model before anything downstream ever
sees it - Step 2's "treat outputs as untrusted advisory data until
reviewed" starts with basic type/shape validation and continues at the
`reviewed` flag on AIAssessmentRecord (zeroshield.assurance.models).
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_METADATA_FIELDS = frozenset({"provider", "model", "generated_at"})


class AIAssessmentBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confidence: float = Field(ge=0.0, le=1.0, description="How confident the assessment is, 0.0-1.0.")
    rationale: str = Field(min_length=1, description="Concise explanation of the assessment.")
    source_ids: list[str] = Field(
        default_factory=list, description="IDs of sources this assessment is grounded in (CVE IDs, experiment IDs, URLs)."
    )
    provider: str = Field(description="AI provider that generated this assessment, e.g. 'gemini'.")
    model: str = Field(description="Model ID that generated this assessment.")
    generated_at: datetime

    @classmethod
    def ai_output_schema(cls) -> dict[str, Any]:
        """JSON Schema for exactly the fields the AI must produce - excludes
        provider/model/generated_at, which the caller fills in after the
        response returns (see module docstring)."""
        schema = cls.model_json_schema()
        properties = {k: v for k, v in schema["properties"].items() if k not in _METADATA_FIELDS}
        required = [f for f in schema.get("required", []) if f not in _METADATA_FIELDS]
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
            **({"$defs": schema["$defs"]} if "$defs" in schema else {}),
        }


class FailurePatternAssessment(AIAssessmentBase):
    """AI's classification of which defensive failure pattern a CVE most
    resembles - advisory only; never used to select a strategy directly.
    Template recommendation (below) is the only thing that acts on it, and
    only by matching against EXISTING allow-listed templates (Step 6)."""

    cve_id: str
    domain: str | None = Field(default=None, description="VPN or TELECOM, if the AI could determine one.")
    failure_pattern: str = Field(description="e.g. 'pre_auth_request_schema_validation'.")
    supporting_evidence: list[str] = Field(default_factory=list)


class MitigationGapAssessment(AIAssessmentBase):
    """Step 5: gaps such as patch-only guidance, unclear recovery,
    unspecified credential rotation, lack of post-compromise trust
    validation. Stored as a suggestion, never a fact, until reviewed."""

    cve_id: str
    gaps: list[str] = Field(min_length=1, description="Each a short, specific mitigation-gap statement.")


class SimilarVulnerabilityRecommendation(AIAssessmentBase):
    """AI's narrative summary layered on top of the deterministic
    correlation engine (zeroshield.intelligence.correlation) - never a
    replacement for it. `similar_cve_ids` here must be a subset of the
    correlation engine's own output, enforced by the caller
    (ResearchAnalystService), so AI can narrate similarity but never invent
    a similar CVE the deterministic engine didn't already surface."""

    cve_id: str
    similar_cve_ids: list[str] = Field(default_factory=list)
    caveat: str = Field(
        default="Similarity is a structured/textual signal, not proof of identical root cause.",
        description="Always shown alongside the recommendation.",
    )


class ValidationTemplateRecommendation(AIAssessmentBase):
    """Step 6: recommends an EXISTING allow-listed template through the
    Domain Pack framework. domain_pack_id/template_id/template_version are
    validated by the caller against zeroshield.domain_packs/templates
    registries before this is ever persisted - the AI selects from a list
    of real options it is given, it never invents an identifier."""

    cve_id: str
    domain_pack_id: str
    template_id: str
    template_version: str


class ExperimentDraftSuggestion(AIAssessmentBase):
    """Step 2: 'draft experiment proposals' - purely advisory text a human
    copies into Experiment Studio (zeroshield.studio.builder) if they agree;
    this schema has no path to zeroshield.studio.build_experiment_draft and
    cannot itself create a version."""

    cve_id: str
    title: str
    research_question: str
    hypothesis: str
    trust_boundary: str
    vendor_mitigation: str
    mitigation_gap: str


class RegressionExplanation(AIAssessmentBase):
    """Step 10: 'AI may explain a regression, not independently declare
    it.' Always generated FROM an already-computed, deterministic
    zeroshield.assurance.regression.RegressionResult - the AI never decides
    whether a regression occurred, only narrates the reasons it is given."""

    control_id: str
    explanation: str
