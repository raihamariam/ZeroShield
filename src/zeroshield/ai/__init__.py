"""ZeroShield AI Research Analyst (V2 Phase 5, Step 1).

AI IS ADVISORY ONLY - see zeroshield.ai.provider's module docstring for the
non-negotiable boundary this whole package is built around. Nothing in this
package can approve an experiment, touch SafetyPolicy, modify evidence,
publish a run job, execute generated code, or change a deterministic
verdict; it only produces schema-validated, untrusted-until-reviewed
assessments (zeroshield.ai.schemas) that a human reviews through the API/UI.
"""

from zeroshield.ai.config import resolve_ai_provider
from zeroshield.ai.provider import AIProvider, AIResponseError, AIUnavailableError
from zeroshield.ai.research_analyst_service import ResearchAnalystService

__all__ = [
    "AIProvider",
    "AIResponseError",
    "AIUnavailableError",
    "ResearchAnalystService",
    "resolve_ai_provider",
]
