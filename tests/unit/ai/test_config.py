"""Provider-resolution tests for zeroshield.ai.config.resolve_ai_provider -
every combination of AI_PROVIDER/GEMINI_API_KEY must degrade to NullAIProvider
rather than raise, except the one valid "gemini + key" combination (Step 1:
"a missing/misconfigured AI_PROVIDER can never prevent the rest of the API
from starting")."""

import pytest

from zeroshield.ai.config import resolve_ai_provider
from zeroshield.ai.gemini_provider import GeminiProvider
from zeroshield.ai.null_provider import NullAIProvider


@pytest.fixture(autouse=True)
def _clean_ai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)


def test_unset_ai_provider_resolves_to_null(monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(resolve_ai_provider(), NullAIProvider)


def test_ai_provider_none_resolves_to_null(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_PROVIDER", "none")
    assert isinstance(resolve_ai_provider(), NullAIProvider)


def test_unknown_ai_provider_resolves_to_null_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("AI_PROVIDER", "openai")
    with caplog.at_level("WARNING"):
        provider = resolve_ai_provider()
    assert isinstance(provider, NullAIProvider)
    assert "Unknown AI_PROVIDER" in caplog.text


def test_gemini_with_key_resolves_to_gemini_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    provider = resolve_ai_provider()
    assert isinstance(provider, GeminiProvider)
    assert provider.is_configured() is True


def test_gemini_missing_key_resolves_to_null_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    with caplog.at_level("WARNING"):
        provider = resolve_ai_provider()
    assert isinstance(provider, NullAIProvider)
    assert "GEMINI_API_KEY is not set" in caplog.text


def test_ai_provider_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_PROVIDER", "GEMINI")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    assert isinstance(resolve_ai_provider(), GeminiProvider)


def test_ai_model_env_var_overrides_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    monkeypatch.setenv("AI_MODEL", "gemini-custom-model")
    provider = resolve_ai_provider()
    assert isinstance(provider, GeminiProvider)
    assert provider._model == "gemini-custom-model"
