"""AI provider selection, configured entirely by environment variables (Step
1: "Configure by environment variables"). Mirrors the guarded, env-gated
construction pattern used for RabbitMQ/MinIO/Postgres elsewhere
(zeroshield.api.dependencies) - unset or unrecognised configuration always
degrades to NullAIProvider rather than raising at import/startup time, so a
missing AI_PROVIDER can never prevent the rest of the API from starting.

  AI_PROVIDER   "gemini" enables GeminiProvider; anything else (including
                unset) resolves to NullAIProvider.
  GEMINI_API_KEY  required for AI_PROVIDER=gemini; missing it also falls
                back to NullAIProvider (GeminiProvider would report itself
                unconfigured anyway - resolved here too so callers can log a
                clear reason at startup instead of only at first-use).
  AI_MODEL      overrides the default model ID (gemini-2.5-flash).
"""

import logging
import os

from zeroshield.ai.provider import AIProvider

logger = logging.getLogger("zeroshield.ai")


def resolve_ai_provider() -> AIProvider:
    provider_name = os.environ.get("AI_PROVIDER", "none").strip().lower()

    if provider_name == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            logger.warning("AI_PROVIDER=gemini but GEMINI_API_KEY is not set - AI features are disabled.")
            from zeroshield.ai.null_provider import NullAIProvider

            return NullAIProvider()

        from zeroshield.ai.gemini_provider import DEFAULT_MODEL, GeminiProvider

        model = os.environ.get("AI_MODEL", DEFAULT_MODEL)
        return GeminiProvider(api_key=api_key, model=model)

    if provider_name not in ("none", ""):
        logger.warning("Unknown AI_PROVIDER '%s' - AI features are disabled.", provider_name)

    from zeroshield.ai.null_provider import NullAIProvider

    return NullAIProvider()
