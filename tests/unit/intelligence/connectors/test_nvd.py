"""Tests NVDConnector against fixture responses shaped exactly like the real
NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0), read from
the official docs at implementation time - see nvd.py's module docstring.
Uses httpx.MockTransport; never touches the real network.
"""

import httpx
import pytest

from zeroshield.intelligence.connectors.base import ConnectorHealth
from zeroshield.intelligence.connectors.http import ConnectorFetchError
from zeroshield.intelligence.connectors.nvd import NVDConnector
from zeroshield.models.vulnerability import VulnerabilitySourceName


def _cve_item(cve_id: str) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "sourceIdentifier": "psirt@fortinet.com",
            "published": "2024-02-08T00:00:00.000",
            "lastModified": "2024-02-09T15:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "desc"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.6, "vectorString": "x", "version": "3.1"}}]
            },
            "weaknesses": [],
            "references": [],
            "configurations": [],
        }
    }


def test_fetch_single_page_yields_all_records() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [_cve_item("CVE-2024-21762"), _cve_item("CVE-2024-21763")],
                "totalResults": 2,
            },
        )

    connector = NVDConnector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    records = list(connector.fetch())
    assert [r.external_id for r in records] == ["CVE-2024-21762", "CVE-2024-21763"]
    assert all(r.source is VulnerabilitySourceName.NVD for r in records)


def test_fetch_paginates_across_multiple_pages() -> None:
    pages = [
        {"vulnerabilities": [_cve_item("CVE-2024-00001")], "totalResults": 3},
        {"vulnerabilities": [_cve_item("CVE-2024-00002")], "totalResults": 3},
        {"vulnerabilities": [_cve_item("CVE-2024-00003")], "totalResults": 3},
    ]
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.params.get("startIndex"))
        return httpx.Response(200, json=pages[len(calls) - 1])

    connector = NVDConnector(
        client=httpx.Client(transport=httpx.MockTransport(handler)), sleep_between_pages=0
    )
    records = list(connector.fetch())
    assert [r.external_id for r in records] == ["CVE-2024-00001", "CVE-2024-00002", "CVE-2024-00003"]
    assert calls == ["0", "1", "2"]


def test_fetch_stops_at_max_pages_safety_cap() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Always claims more results exist than one page returns, to prove
        # max_pages is what stops iteration, not totalResults.
        return httpx.Response(200, json={"vulnerabilities": [_cve_item("CVE-2024-00001")], "totalResults": 999999})

    connector = NVDConnector(
        client=httpx.Client(transport=httpx.MockTransport(handler)), max_pages=3, sleep_between_pages=0
    )
    records = list(connector.fetch())
    assert len(records) == 3


def test_fetch_uses_date_window_when_since_given() -> None:
    from datetime import UTC, datetime

    seen_params = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_params.update(request.url.params)
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    connector = NVDConnector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    list(connector.fetch(since=datetime(2024, 1, 1, tzinfo=UTC)))
    assert "lastModStartDate" in seen_params
    assert "lastModEndDate" in seen_params


def test_fetch_sends_api_key_header_when_configured() -> None:
    seen_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    connector = NVDConnector(client=httpx.Client(transport=httpx.MockTransport(handler)), api_key="secret123")
    list(connector.fetch())
    assert seen_headers.get("apikey") == "secret123"


def test_fetch_raises_on_unexpected_response_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    connector = NVDConnector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(ConnectorFetchError, match="vulnerabilities"):
        list(connector.fetch())


def test_health_reports_available_on_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    connector = NVDConnector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    health = connector.health()
    assert isinstance(health, ConnectorHealth)
    assert health.available is True
    assert health.source is VulnerabilitySourceName.NVD


def test_health_reports_unavailable_on_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    connector = NVDConnector(client=httpx.Client(transport=httpx.MockTransport(handler)))
    health = connector.health()
    assert health.available is False
    assert health.detail is not None
