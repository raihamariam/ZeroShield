"""Tests GitHubAdvisoryConnector against fixtures shaped like the real GitHub
Security Advisories API (https://api.github.com/advisories), read from the
official docs at implementation time - see github_advisory.py's module
docstring. Uses httpx.MockTransport; exercises Link-header pagination, the
GitHub-standard cursor mechanism.
"""

import httpx
import pytest

from zeroshield.intelligence.connectors.github_advisory import GitHubAdvisoryConnector
from zeroshield.intelligence.connectors.http import ConnectorFetchError
from zeroshield.models.vulnerability import VulnerabilitySourceName


def _advisory(ghsa_id: str, cve_id: str | None = "CVE-2024-21762") -> dict:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": "OpenVPN buffer overflow",
        "description": "detailed description",
        "severity": "critical",
        "cvss_severities": {"cvss_v3": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N"}},
        "cwes": [{"cwe_id": "CWE-787", "name": "Out-of-bounds Write"}],
        "published_at": "2024-02-08T00:00:00Z",
        "updated_at": "2024-02-09T00:00:00Z",
        "references": ["https://github.com/advisories/" + ghsa_id],
        "vulnerabilities": [],
    }


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_yields_all_advisories_single_page() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_advisory("GHSA-aaaa"), _advisory("GHSA-bbbb")])

    connector = GitHubAdvisoryConnector(client=_client(handler))
    records = list(connector.fetch())
    assert [r.external_id for r in records] == ["GHSA-aaaa", "GHSA-bbbb"]
    assert all(r.source is VulnerabilitySourceName.GITHUB_ADVISORY for r in records)


def test_fetch_follows_link_header_pagination() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(
                200,
                json=[_advisory("GHSA-page1")],
                headers={"Link": '<https://api.github.com/advisories?page=2>; rel="next"'},
            )
        return httpx.Response(200, json=[_advisory("GHSA-page2")])

    connector = GitHubAdvisoryConnector(client=_client(handler))
    records = list(connector.fetch())
    assert [r.external_id for r in records] == ["GHSA-page1", "GHSA-page2"]
    assert len(calls) == 2


def test_fetch_stops_when_no_next_link() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_advisory("GHSA-only")])

    connector = GitHubAdvisoryConnector(client=_client(handler))
    assert len(list(connector.fetch())) == 1


def test_fetch_sends_bearer_token_when_configured() -> None:
    seen_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(200, json=[])

    connector = GitHubAdvisoryConnector(client=_client(handler), token="ghp_secret")
    list(connector.fetch())
    assert seen_headers.get("authorization") == "Bearer ghp_secret"


def test_fetch_omits_authorization_header_when_no_token() -> None:
    seen_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(200, json=[])

    connector = GitHubAdvisoryConnector(client=_client(handler), token=None)
    list(connector.fetch())
    assert "authorization" not in seen_headers


def test_fetch_raises_on_non_list_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "a list"})

    connector = GitHubAdvisoryConnector(client=_client(handler))
    with pytest.raises(ConnectorFetchError, match="not a list"):
        list(connector.fetch())


def test_fetch_raises_on_error_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="rate limited")

    connector = GitHubAdvisoryConnector(client=_client(handler))
    with pytest.raises(ConnectorFetchError, match="403"):
        list(connector.fetch())


def test_health_available_on_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    connector = GitHubAdvisoryConnector(client=_client(handler))
    assert connector.health().available is True
