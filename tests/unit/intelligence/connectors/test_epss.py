"""Tests EPSSConnector against fixtures shaped like the real FIRST.org EPSS
API (https://api.first.org/data/v1/epss), read from the official docs at
implementation time - see epss.py's module docstring. Uses httpx.MockTransport.
"""

import httpx
import pytest

from zeroshield.intelligence.connectors.epss import EPSSConnector
from zeroshield.intelligence.connectors.http import ConnectorFetchError
from zeroshield.models.vulnerability import VulnerabilitySourceName


def _entry(cve: str) -> dict:
    return {"cve": cve, "epss": "0.94500", "percentile": "0.99120", "date": "2026-08-17"}


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_yields_all_records_single_page() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "OK", "status-code": 200, "version": "1.0", "access": "public",
                "total": 2, "offset": 0, "limit": 1000,
                "data": [_entry("CVE-2024-21762"), _entry("CVE-2024-21763")],
            },
        )

    connector = EPSSConnector(client=_client(handler))
    records = list(connector.fetch())
    assert [r.external_id for r in records] == ["CVE-2024-21762", "CVE-2024-21763"]
    assert all(r.source is VulnerabilitySourceName.EPSS for r in records)


def test_fetch_paginates_via_offset() -> None:
    pages = [
        {"total": 3, "offset": 0, "limit": 1, "data": [_entry("CVE-2024-00001")]},
        {"total": 3, "offset": 1, "limit": 1, "data": [_entry("CVE-2024-00002")]},
        {"total": 3, "offset": 2, "limit": 1, "data": [_entry("CVE-2024-00003")]},
    ]
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.params.get("offset"))
        return httpx.Response(200, json=pages[len(calls) - 1])

    connector = EPSSConnector(client=_client(handler))
    records = list(connector.fetch())
    assert len(records) == 3
    assert calls == ["0", "1", "2"]


def test_fetch_uses_date_param_for_historical_snapshot() -> None:
    from datetime import UTC, datetime

    seen_params = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_params.update(request.url.params)
        return httpx.Response(200, json={"total": 0, "offset": 0, "limit": 1000, "data": []})

    connector = EPSSConnector(client=_client(handler))
    list(connector.fetch(since=datetime(2024, 1, 1, tzinfo=UTC)))
    assert seen_params.get("date") == "2024-01-01"


def test_fetch_raises_on_unexpected_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"nope": True})

    connector = EPSSConnector(client=_client(handler))
    with pytest.raises(ConnectorFetchError, match="data"):
        list(connector.fetch())


def test_health_available_on_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total": 0, "offset": 0, "limit": 1, "data": []})

    connector = EPSSConnector(client=_client(handler))
    assert connector.health().available is True
