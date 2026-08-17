"""NVD CVE API 2.0 connector.

Schema/behaviour grounded in the official documentation read at implementation
time (https://nvd.nist.gov/developers/vulnerabilities,
https://nvd.nist.gov/developers/start-here - August 2026):

- Base URL: https://services.nvd.nist.gov/rest/json/cves/2.0
- Pagination: startIndex (offset) / resultsPerPage (max 2000) / totalResults
- Incremental sync: lastModStartDate/lastModEndDate, ISO-8601, max 120-day window
- Rate limit: 5 requests/30s without an API key, 50 requests/30s with one
  (header `apiKey`); NVD's own guidance recommends sleeping between requests
  rather than bursting even under the limit.
- Response: {"vulnerabilities": [{"cve": {id, sourceIdentifier, published,
  lastModified, vulnStatus, descriptions[], metrics.cvssMetricV31/V30/V2[],
  weaknesses[], references[], ...}}], "totalResults": int}
"""

import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import httpx

from zeroshield.intelligence.connectors.base import (
    ConnectorHealth,
    RawIntelligenceRecord,
    ThreatIntelligenceConnector,
)
from zeroshield.intelligence.connectors.http import (
    ConnectorFetchError,
    build_default_client,
    fetch_json,
)
from zeroshield.models.vulnerability import VulnerabilitySourceName

_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_DATE_WINDOW = timedelta(days=120)
_RESULTS_PER_PAGE = 2000
_DEFAULT_SLEEP_BETWEEN_PAGES = 6.0  # seconds; NVD's own documented recommendation without an API key


class NVDConnector(ThreatIntelligenceConnector):
    source = VulnerabilitySourceName.NVD

    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        base_url: str = _BASE_URL,
        max_pages: int = 5,
        sleep_between_pages: float = _DEFAULT_SLEEP_BETWEEN_PAGES,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self._client = client or build_default_client()
        self._base_url = base_url
        # Guards a `since=None` ("full") sync from accidentally attempting to
        # pull all ~380,000 NVD records in one call - deliberate, adjustable
        # safety default, not a schema limitation.
        self._max_pages = max_pages
        self._sleep_between_pages = sleep_between_pages

    def _headers(self) -> dict[str, str]:
        return {"apiKey": self._api_key} if self._api_key else {}

    def fetch(self, *, since: datetime | None = None) -> Iterator[RawIntelligenceRecord]:
        params: dict[str, str | int] = {"resultsPerPage": _RESULTS_PER_PAGE}
        if since is not None:
            end = min(since + _MAX_DATE_WINDOW, datetime.now(UTC))
            params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

        start_index = 0
        for page in range(self._max_pages):
            page_params = {**params, "startIndex": start_index}
            body = fetch_json(
                self._client, self._base_url, params=page_params, headers=self._headers()
            )
            if not isinstance(body, dict) or "vulnerabilities" not in body:
                raise ConnectorFetchError(
                    "NVD response missing expected 'vulnerabilities' key - upstream schema may "
                    "have changed"
                )

            items = body["vulnerabilities"]
            if not isinstance(items, list):
                raise ConnectorFetchError("NVD 'vulnerabilities' field was not a list")

            for entry in items:
                cve = entry.get("cve") if isinstance(entry, dict) else None
                if not isinstance(cve, dict):
                    continue
                yield RawIntelligenceRecord(
                    source=self.source, external_id=str(cve.get("id", "")), raw=cve
                )

            total_results = body.get("totalResults", 0)
            start_index += len(items)
            if len(items) == 0 or start_index >= total_results:
                break
            if page < self._max_pages - 1 and self._sleep_between_pages > 0:
                time.sleep(self._sleep_between_pages)

    def health(self) -> ConnectorHealth:
        try:
            fetch_json(
                self._client,
                self._base_url,
                params={"resultsPerPage": 1},
                headers=self._headers(),
                max_retries=0,
            )
        except ConnectorFetchError as exc:
            return ConnectorHealth(source=self.source, available=False, detail=str(exc))
        return ConnectorHealth(source=self.source, available=True, detail=None)
