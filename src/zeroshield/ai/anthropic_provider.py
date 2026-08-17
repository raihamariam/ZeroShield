"""Anthropic implementation of AIProvider (V2 Phase 5, Step 1).

Uses the official `anthropic` SDK's structured-outputs feature
(`output_config.format`) so every response is guaranteed to parse as JSON
matching the caller's schema - never a hand-rolled "ask nicely for JSON and
regex it out of the response text" approach. Requires the optional "ai"
extra (`pip install "zeroshield[ai]"`); imported lazily so the rest of the
application never needs the `anthropic` package installed - same guarded-
optional-dependency pattern as MinIO/pika/SQLAlchemy elsewhere in this
codebase (see zeroshield.api.dependencies.get_run_repository).
"""

import logging

from zeroshield.ai.provider import (
    AIGenerationRequest,
    AIGenerationResult,
    AIProvider,
    AIResponseError,
    AIUnavailableError,
)

logger = logging.getLogger("zeroshield.ai")

DEFAULT_MODEL = "claude-opus-5"


class AnthropicProvider(AIProvider):
    def __init__(self, *, api_key: str | None, model: str = DEFAULT_MODEL) -> None:
        self._api_key = api_key
        self._model = model

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def generate_structured(self, request: AIGenerationRequest) -> AIGenerationResult:
        if not self.is_configured():
            raise AIUnavailableError("ANTHROPIC_API_KEY is not configured.")

        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the "ai" extra installed
            raise AIUnavailableError(
                "The 'anthropic' package is not installed - install the 'ai' extra to enable AI features."
            ) from exc

        client = anthropic.Anthropic(api_key=self._api_key)

        try:
            response = client.messages.create(
                model=self._model,
                max_tokens=request.max_tokens,
                system=request.system,
                output_config={
                    "effort": "medium",
                    "format": {
                        "type": "json_schema",
                        "schema": request.json_schema,
                    },
                },
                messages=[{"role": "user", "content": request.prompt}],
            )
        except anthropic.APIConnectionError as exc:
            raise AIUnavailableError(f"Could not reach the Anthropic API: {exc}") from exc
        except anthropic.AuthenticationError as exc:
            raise AIUnavailableError(f"Anthropic API authentication failed: {exc}") from exc
        except anthropic.RateLimitError as exc:
            raise AIUnavailableError(f"Anthropic API rate limit exceeded: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise AIResponseError(f"Anthropic API returned an error: {exc}") from exc
        except anthropic.APIError as exc:
            # Catch-all for any other SDK exception (e.g. APITimeoutError) not
            # covered above - Step 1 requires "AI failure cannot break validation
            # execution"; an unmapped SDK exception must degrade to an advisory
            # 503, never propagate as an unhandled 500.
            raise AIUnavailableError(f"Anthropic API call failed: {exc}") from exc

        if response.stop_reason == "refusal":
            raise AIResponseError("The AI provider declined to answer this request (safety refusal).")

        text = next((block.text for block in response.content if block.type == "text"), None)
        if text is None:
            raise AIResponseError("The AI provider returned no text content to parse.")

        import json

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AIResponseError(f"The AI provider's response was not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise AIResponseError("The AI provider's response was valid JSON but not a JSON object.")

        return AIGenerationResult(data=data, provider="anthropic", model=response.model)
