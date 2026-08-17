"""No-op AIProvider used whenever AI is disabled or unconfigured (AI_PROVIDER
unset/"none", or set to a provider missing its credentials). Guarantees the
Step 1 requirement "Core ZeroShield must still work when AI is disabled/
unavailable; AI failure cannot break validation execution" by construction:
every AI-consuming route calls this and gets a clean AIUnavailableError to
turn into an honest "AI is currently unavailable" response, never a crash.
"""

from zeroshield.ai.provider import (
    AIGenerationRequest,
    AIGenerationResult,
    AIProvider,
    AIUnavailableError,
)


class NullAIProvider(AIProvider):
    def is_configured(self) -> bool:
        return False

    def generate_structured(self, request: AIGenerationRequest) -> AIGenerationResult:
        raise AIUnavailableError("No AI provider is configured (AI_PROVIDER is unset or 'none').")
