"""GeminiProvider tests - mocks the google-genai SDK entirely (patches
google.genai.Client), never makes a real network call. Covers V2 Phase 5,
Step 13's AI-specific test requirements plus the provider-specific failure
modes called out for the Gemini migration: auth failure, rate limiting,
server errors, connectivity/timeouts, SDK-not-installed, and unusable
structured-output responses."""

import sys

import pytest

from zeroshield.ai.gemini_provider import DEFAULT_MODEL, GeminiProvider
from zeroshield.ai.provider import AIGenerationRequest, AIResponseError, AIUnavailableError

REQUEST = AIGenerationRequest(
    system="system prompt",
    prompt="user prompt",
    json_schema={"type": "object", "properties": {"x": {"type": "string"}}},
    schema_name="test_schema",
)


class _FakeCandidate:
    def __init__(self, finish_reason: str | None = None) -> None:
        self.finish_reason = finish_reason


class _FakeResponse:
    def __init__(self, text: str | None, *, candidates: list | None = None, model_version: str | None = None) -> None:
        self.text = text
        self.candidates = candidates if candidates is not None else [_FakeCandidate()]
        self.model_version = model_version


class _FakeModels:
    def __init__(self, *, response: object | None = None, error: Exception | None = None) -> None:
        self._response = response
        self._error = error
        self.last_kwargs: dict | None = None

    def generate_content(self, **kwargs: object) -> object:
        self.last_kwargs = kwargs
        if self._error is not None:
            raise self._error
        return self._response


class _FakeClient:
    def __init__(self, models: _FakeModels) -> None:
        self.models = models


def _patch_client(monkeypatch: pytest.MonkeyPatch, models: _FakeModels) -> None:
    import google.genai

    monkeypatch.setattr(google.genai, "Client", lambda api_key: _FakeClient(models))


# -- is_configured -------------------------------------------------------------

def test_unconfigured_provider_has_no_api_key() -> None:
    assert GeminiProvider(api_key=None).is_configured() is False


def test_configured_provider_has_an_api_key() -> None:
    assert GeminiProvider(api_key="key").is_configured() is True


def test_unconfigured_provider_raises_before_touching_the_sdk() -> None:
    provider = GeminiProvider(api_key=None)
    with pytest.raises(AIUnavailableError, match="GEMINI_API_KEY"):
        provider.generate_structured(REQUEST)


# -- successful structured response --------------------------------------------

def test_successful_response_is_parsed_and_stamped(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse('{"x": "value"}', model_version="gemini-2.5-flash-001"))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    result = provider.generate_structured(REQUEST)
    assert result.data == {"x": "value"}
    assert result.provider == "gemini"
    assert result.model == "gemini-2.5-flash-001"


def test_response_without_model_version_falls_back_to_configured_model(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse('{"x": "value"}'))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key", model="gemini-custom")
    result = provider.generate_structured(REQUEST)
    assert result.model == "gemini-custom"


def test_default_model_is_a_flash_class_model() -> None:
    assert "flash" in DEFAULT_MODEL


def test_request_is_forwarded_with_schema_and_system_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    from google.genai import types

    models = _FakeModels(response=_FakeResponse('{"x": "value"}'))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    provider.generate_structured(REQUEST)
    assert models.last_kwargs is not None
    assert models.last_kwargs["contents"] == REQUEST.prompt
    config = models.last_kwargs["config"]
    assert isinstance(config, types.GenerateContentConfig)
    assert config.system_instruction == REQUEST.system
    assert config.response_json_schema == REQUEST.json_schema
    assert config.response_mime_type == "application/json"


# -- malformed / unusable output -------------------------------------------------

def test_malformed_json_raises_ai_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse("not json"))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIResponseError, match="not valid JSON"):
        provider.generate_structured(REQUEST)


def test_non_object_json_raises_ai_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse("[1, 2, 3]"))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIResponseError, match="not a JSON object"):
        provider.generate_structured(REQUEST)


def test_missing_response_content_raises_ai_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse(None))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIResponseError, match="no text content"):
        provider.generate_structured(REQUEST)


def test_empty_text_raises_ai_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse(""))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIResponseError, match="no text content"):
        provider.generate_structured(REQUEST)


def test_safety_refusal_raises_ai_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse(None, candidates=[_FakeCandidate(finish_reason="SAFETY")]))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIResponseError, match="declined to answer"):
        provider.generate_structured(REQUEST)


def test_unusable_response_with_no_candidates_raises_ai_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(response=_FakeResponse(None, candidates=[]))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIResponseError):
        provider.generate_structured(REQUEST)


# -- SDK-level failures -----------------------------------------------------------

def test_authentication_failure_raises_ai_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from google.genai.errors import ClientError

    models = _FakeModels(error=ClientError(401, {"error": {"message": "invalid API key"}}))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="bad-key")
    with pytest.raises(AIUnavailableError, match="authentication failed"):
        provider.generate_structured(REQUEST)


def test_forbidden_is_treated_as_authentication_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from google.genai.errors import ClientError

    models = _FakeModels(error=ClientError(403, {"error": {"message": "forbidden"}}))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIUnavailableError, match="authentication failed"):
        provider.generate_structured(REQUEST)


def test_rate_limit_raises_ai_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from google.genai.errors import ClientError

    models = _FakeModels(error=ClientError(429, {"error": {"message": "quota exceeded"}}))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIUnavailableError, match="rate limit"):
        provider.generate_structured(REQUEST)


def test_other_client_error_raises_ai_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from google.genai.errors import ClientError

    models = _FakeModels(error=ClientError(400, {"error": {"message": "bad request"}}))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIResponseError, match="rejected the request"):
        provider.generate_structured(REQUEST)


def test_server_error_raises_ai_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from google.genai.errors import ServerError

    models = _FakeModels(error=ServerError(503, {"error": {"message": "upstream unavailable"}}))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIUnavailableError, match="server error"):
        provider.generate_structured(REQUEST)


def test_connectivity_failure_raises_ai_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(error=ConnectionError("could not connect"))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIUnavailableError, match="Could not reach the Gemini API"):
        provider.generate_structured(REQUEST)


def test_timeout_raises_ai_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    models = _FakeModels(error=TimeoutError("timed out"))
    _patch_client(monkeypatch, models)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIUnavailableError, match="Could not reach the Gemini API"):
        provider.generate_structured(REQUEST)


def test_sdk_not_installed_raises_ai_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import google

    monkeypatch.setitem(sys.modules, "google.genai", None)
    monkeypatch.delattr(google, "genai", raising=False)
    provider = GeminiProvider(api_key="key")
    with pytest.raises(AIUnavailableError, match="not installed"):
        provider.generate_structured(REQUEST)
