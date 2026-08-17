"""GitHub Security Advisories (GHSA) connector - the one concrete
VendorAdvisoryConnector implemented in V2 Phase 2.

Chosen because it is the one vendor/ecosystem source with reliable,
documented, officially-supported programmatic access relevant to VPN/Telecom
open-source components (e.g. OpenVPN, strongSwan, Asterisk, FreeSWITCH all
publish through GitHub-hosted repositories and their advisories appear here) -
per Step 2's instruction not to add brittle scraping just to claim coverage,
no other VPN/Telecom vendor (Fortinet, Ivanti, Cisco, etc.) publishes a
stable, documented public advisory API as of this phase; see the Phase 2
Completion Report.

Schema grounded in the official documentation read at implementation time
(https://docs.github.com/en/rest/security-advisories/global-advisories -
August 2026):

- Base URL: https://api.github.com/advisories
- Unauthenticated access is allowed (GitHub's standard unauthenticated REST
  rate limit applies, 60 requests/hour/IP); set GITHUB_TOKEN to authenticate
  via `Authorization: Bearer <token>` for the standard authenticated limit.
- Pagination: standard GitHub Link-header cursor pagination (rel="next").
- Response: array of {ghsa_id, cve_id, summary, description, severity,
  cvss_severities.{cvss_v3,cvss_v4}.{score,vector_string}, cwes[], published_at,
  updated_at, references[], vulnerabilities[]}.
"""

import os
from collections.abc import Iterator
from datetime import datetime

import httpx

from zeroshield.intelligence.connectors.base import ConnectorHealth, RawIntelligenceRecord
from zeroshield.intelligence.connectors.http import ConnectorFetchError, build_default_client
from zeroshield.intelligence.connectors.vendor_advisory import VendorAdvisoryConnector
from zeroshield.models.vulnerability import VulnerabilitySourceName

_BASE_URL = "https://api.github.com/advisories"
_PER_PAGE = 100


class GitHubAdvisoryConnector(VendorAdvisoryConnector):
    source = VulnerabilitySourceName.GITHUB_ADVISORY

    def __init__(
        self,
        *,
        token: str | None = None,
        client: httpx.Client | None = None,
        base_url: str = _BASE_URL,
        max_pages: int = 5,
    ) -> None:
        self._token = token if token is not None else os.environ.get("GITHUB_TOKEN")
        self._client = client or build_default_client()
        self._base_url = base_url
        self._max_pages = max_pages

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def fetch(self, *, since: datetime | None = None) -> Iterator[RawIntelligenceRecord]:
        url = self._base_url
        params: dict[str, str | int] = {"type": "reviewed", "per_page": _PER_PAGE}
        if since is not None:
            params["updated"] = f">={since.date().isoformat()}"

        # None on every request after the first - a Link-header "next" URL
        # already carries its own encoded query string.
        next_params: dict[str, str | int] | None = params
        for _page in range(self._max_pages):
            response = self._get(url, next_params)
            body = response.json()
            if not isinstance(body, list):
                raise ConnectorFetchError(
                    "GitHub Advisories response was not a list - upstream schema may have changed"
                )
            for entry in body:
                if not isinstance(entry, dict):
                    continue
                yield RawIntelligenceRecord(
                    source=self.source, external_id=str(entry.get("ghsa_id", "")), raw=entry
                )

            next_url = response.links.get("next", {}).get("url")
            if not next_url or not body:
                break
            url, next_params = next_url, None

    def _get(self, url: str, params: dict[str, str | int] | None) -> httpx.Response:
        try:
            response = self._client.get(url, params=params, headers=self._headers())
        except httpx.TransportError as exc:
            raise ConnectorFetchError(f"request to {url} failed: {exc}") from exc
        if response.status_code >= 300:
            raise ConnectorFetchError(
                f"request to {url} failed with status {response.status_code}: "
                f"{response.text[:200]!r}"
            )
        return response

    def health(self) -> ConnectorHealth:
        try:
            self._get(self._base_url, {"per_page": 1})
        except ConnectorFetchError as exc:
            return ConnectorHealth(source=self.source, available=False, detail=str(exc))
        return ConnectorHealth(source=self.source, available=True, detail=None)
