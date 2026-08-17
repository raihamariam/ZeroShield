"""Tests the shared fetch_json helper's retry/backoff, non-retryable-status,
and size-limit behaviour using httpx.MockTransport - no real network access,
per Step 12: "do not make CI depend on live internet."
"""

import httpx
import pytest

from zeroshield.intelligence.connectors.http import ConnectorFetchError, fetch_json


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_json_returns_parsed_body_on_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    body = fetch_json(_client(handler), "https://example.test/x")
    assert body == {"ok": True}


def test_fetch_json_retries_retryable_status_then_succeeds() -> None:
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    sleeps = []
    body = fetch_json(
        _client(handler), "https://example.test/x", max_retries=3, sleep=lambda s: sleeps.append(s)
    )
    assert body == {"ok": True}
    assert len(attempts) == 3
    assert len(sleeps) == 2  # slept between attempts 1->2 and 2->3, not after final success


def test_fetch_json_raises_after_exhausting_retries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    with pytest.raises(ConnectorFetchError, match="failed after"):
        fetch_json(_client(handler), "https://example.test/x", max_retries=2, sleep=lambda s: None)


def test_fetch_json_never_retries_non_retryable_4xx() -> None:
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(404, text="not found")

    with pytest.raises(ConnectorFetchError, match="non-retryable status 404"):
        fetch_json(_client(handler), "https://example.test/x", max_retries=3, sleep=lambda s: None)
    assert len(attempts) == 1


def test_fetch_json_raises_on_transport_error_after_retries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(ConnectorFetchError, match="failed after"):
        fetch_json(_client(handler), "https://example.test/x", max_retries=1, sleep=lambda s: None)


def test_fetch_json_rejects_non_json_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    with pytest.raises(ConnectorFetchError, match="not valid JSON"):
        fetch_json(_client(handler), "https://example.test/x", max_retries=0)


def test_fetch_json_rejects_oversized_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (26 * 1024 * 1024))

    with pytest.raises(ConnectorFetchError, match="safety limit"):
        fetch_json(_client(handler), "https://example.test/x", max_retries=0)


def test_fetch_json_sends_expected_headers() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["user_agent"] = request.headers.get("user-agent")
        return httpx.Response(200, json={})

    from zeroshield.intelligence.connectors.http import build_default_client

    client = httpx.Client(transport=httpx.MockTransport(handler))
    client.headers.update(build_default_client().headers)
    fetch_json(client, "https://example.test/x")
    assert "ZeroShield-ThreatIntel" in seen["user_agent"]
