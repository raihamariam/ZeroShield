"""Google Gemini implementation of AIProvider - ZeroShield's only external
LLM provider.

Uses the official `google-genai` SDK's structured-output support
(`GenerateContentConfig(response_mime_type="application/json",
response_json_schema=...)`, which - unlike the older `response_schema` field
- accepts the full JSON Schema `request.json_schema` produced by
`zeroshield.ai.schemas.AIAssessmentBase.ai_output_schema()`, `$defs`/`$ref`
and `additionalProperties: False` included, so every response is guaranteed
to parse as JSON matching the caller's schema - never a hand-rolled "ask
nicely for JSON and regex it out of the response text" approach. Requires
the optional "ai" extra (`pip install "zeroshield[ai]"`); imported lazily so
the rest of the application never needs the `google-genai` package
installed - same guarded-optional-dependency pattern as MinIO/pika/
SQLAlchemy elsewhere in this codebase (see
zeroshield.api.dependencies.get_run_repository).
"""

import json
import logging

from zeroshield.ai.provider import (
    AIGenerationRequest,
    AIGenerationResult,
    AIProvider,
    AIResponseError,
    AIUnavailableError,
)

logger = logging.getLogger("zeroshield.ai")

# Gemini 2.5 Flash: current Flash-class model with structured-output support,
# strong reasoning-per-cost for advisory security analysis, and practical
# free-tier availability for developer/demo use. Override via AI_MODEL if a
# newer model is preferred - nothing else in this module hardcodes an ID.
DEFAULT_MODEL = "gemini-2.5-flash"


class GeminiProvider(AIProvider):
    def __init__(self, *, api_key: str | None, model: str = DEFAULT_MODEL) -> None:
        self._api_key = api_key
        self._model = model

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def generate_structured(self, request: AIGenerationRequest) -> AIGenerationResult:
        if not self.is_configured():
            raise AIUnavailableError("GEMINI_API_KEY is not configured.")

        try:
            from google import genai
            from google.genai import types
            from google.genai.errors import APIError, ClientError, ServerError
        except ImportError as exc:  # pragma: no cover - exercised only without the "ai" extra installed
            raise AIUnavailableError(
                "The 'google-genai' package is not installed - install the 'ai' extra to enable AI features."
            ) from exc

        client = genai.Client(api_key=self._api_key)

        try:
            response = client.models.generate_content(
                model=self._model,
                contents=request.prompt,
                config=types.GenerateContentConfig(
                    system_instruction=request.system,
                    response_mime_type="application/json",
                    response_json_schema=request.json_schema,
                    max_output_tokens=request.max_tokens,
                ),
            )
        except ClientError as exc:
            code = getattr(exc, "code", None)
            if code in (401, 403):
                raise AIUnavailableError(f"Gemini API authentication failed: {exc}") from exc
            if code == 429:
                raise AIUnavailableError(f"Gemini API rate limit exceeded: {exc}") from exc
            raise AIResponseError(f"Gemini API rejected the request: {exc}") from exc
        except ServerError as exc:
            raise AIUnavailableError(f"Gemini API server error: {exc}") from exc
        except APIError as exc:
            # Catch-all for any other SDK API exception not covered above.
            raise AIUnavailableError(f"Gemini API call failed: {exc}") from exc
        except Exception as exc:
            # Connectivity failures/timeouts surface as transport-level exceptions
            # (not an APIError subclass) - Step 1 requires "AI failure cannot break
            # validation execution"; anything unmapped must degrade to an advisory
            # 503, never propagate as an unhandled 500.
            raise AIUnavailableError(f"Could not reach the Gemini API: {exc}") from exc

        candidates = getattr(response, "candidates", None) or []
        finish_reason = getattr(candidates[0], "finish_reason", None) if candidates else None
        if finish_reason is not None and str(finish_reason).upper() in ("SAFETY", "RECITATION", "PROHIBITED_CONTENT"):
            raise AIResponseError(f"The AI provider declined to answer this request ({finish_reason}).")

        text = getattr(response, "text", None)
        if not text:
            raise AIResponseError("The AI provider returned no text content to parse.")

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AIResponseError(f"The AI provider's response was not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise AIResponseError("The AI provider's response was valid JSON but not a JSON object.")

        model_version = getattr(response, "model_version", None) or self._model
        return AIGenerationResult(data=data, provider="gemini", model=model_version)
