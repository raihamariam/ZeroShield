"""AI provider selection, configured entirely by environment variables (Step
1: "Configure by environment variables"). Mirrors the guarded, env-gated
construction pattern used for RabbitMQ/MinIO/Postgres elsewhere
(zeroshield.api.dependencies) - unset or unrecognised configuration always
degrades to NullAIProvider rather than raising at import/startup time, so a
missing AI_PROVIDER can never prevent the rest of the API from starting.

  AI_PROVIDER   "anthropic" enables AnthropicProvider; anything else
                (including unset) resolves to NullAIProvider.
  ANTHROPIC_API_KEY  required for AI_PROVIDER=anthropic; missing it also
                falls back to NullAIProvider (AnthropicProvider would report
                itself unconfigured anyway - resolved here too so callers
                can log a clear reason at startup instead of only at
                first-use).
  AI_MODEL      overrides the default model ID (claude-opus-5).
"""

import logging
import os

from zeroshield.ai.provider import AIProvider

logger = logging.getLogger("zeroshield.ai")


def resolve_ai_provider() -> AIProvider:
    provider_name = os.environ.get("AI_PROVIDER", "none").strip().lower()

    if provider_name == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("AI_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set - AI features are disabled.")
            from zeroshield.ai.null_provider import NullAIProvider

            return NullAIProvider()

        from zeroshield.ai.anthropic_provider import DEFAULT_MODEL, AnthropicProvider

        model = os.environ.get("AI_MODEL", DEFAULT_MODEL)
        return AnthropicProvider(api_key=api_key, model=model)

    if provider_name not in ("none", ""):
        logger.warning("Unknown AI_PROVIDER '%s' - AI features are disabled.", provider_name)

    from zeroshield.ai.null_provider import NullAIProvider

    return NullAIProvider()
