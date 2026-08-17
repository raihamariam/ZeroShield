"""Tests CISAKEVConnector against a fixture shaped exactly like the real
catalog (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
read from the official page at implementation time - see cisa_kev.py's
module docstring. Uses httpx.MockTransport; never touches the real network.
"""

from datetime import UTC, datetime

import httpx
import pytest

from zeroshield.intelligence.connectors.cisa_kev import CISAKEVConnector
from zeroshield.intelligence.connectors.http import ConnectorFetchError
from zeroshield.models.vulnerability import VulnerabilitySourceName

_CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.08.14",
    "dateReleased": "2026-08-14T16:34:49.0391Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-21762",
            "vendorProject": "Fortinet",
            "product": "FortiOS",
            "vulnerabilityName": "Fortinet FortiOS Out-of-Bounds Write Vulnerability",
            "dateAdded": "2024-02-09",
            "shortDescription": "desc",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2024-02-16",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
            "cwes": ["CWE-787"],
        },
        {
            "cveID": "CVE-2023-20198",
            "vendorProject": "Cisco",
            "product": "IOS XE Software",
            "vulnerabilityName": "Cisco IOS XE Web UI Privilege Escalation",
            "dateAdded": "2023-10-16",
            "shortDescription": "desc",
            "requiredAction": "Apply mitigations.",
            "dueDate": "2023-10-20",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-420"],
        },
    ],
}


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_yields_every_entry() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_CATALOG)

    connector = CISAKEVConnector(client=_client(handler))
    records = list(connector.fetch())
    assert [r.external_id for r in records] == ["CVE-2024-21762", "CVE-2023-20198"]
    assert all(r.source is VulnerabilitySourceName.CISA_KEV for r in records)


def test_fetch_filters_client_side_by_since() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_CATALOG)

    connector = CISAKEVConnector(client=_client(handler))
    records = list(connector.fetch(since=datetime(2024, 1, 1, tzinfo=UTC)))
    assert [r.external_id for r in records] == ["CVE-2024-21762"]  # 2023 entry filtered out


def test_fetch_raises_on_unexpected_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "a catalog"})

    connector = CISAKEVConnector(client=_client(handler))
    with pytest.raises(ConnectorFetchError, match="vulnerabilities"):
        list(connector.fetch())


def test_health_available_on_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_CATALOG)

    connector = CISAKEVConnector(client=_client(handler))
    health = connector.health()
    assert health.available is True


def test_health_unavailable_on_network_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns failure")

    connector = CISAKEVConnector(client=_client(handler))
    health = connector.health()
    assert health.available is False
