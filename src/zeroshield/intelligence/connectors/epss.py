"""FIRST.org EPSS API connector.

Schema grounded in the official documentation read at implementation time
(https://api.first.org/epss/, https://www.first.org/epss/api - August 2026):

- Base URL: https://api.first.org/data/v1/epss
- Free, no registration required (currently documented as BETA status).
- Pagination: offset / limit; response includes total/offset/limit.
- `date` (YYYY-MM-DD): returns that day's historical EPSS/percentile snapshot
  instead of the current one - EPSS has no "changed since" filter, so
  incremental sync here means "fetch the snapshot for a specific date", not a
  delta feed.
- Response: {"status", "status-code", "version", "access", "total", "offset",
  "limit", "data": [{"cve", "epss", "percentile", "date"}]}
"""

from collections.abc import Iterator
from datetime import datetime

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

_BASE_URL = "https://api.first.org/data/v1/epss"
_PAGE_LIMIT = 1000


class EPSSConnector(ThreatIntelligenceConnector):
    source = VulnerabilitySourceName.EPSS

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        base_url: str = _BASE_URL,
        max_pages: int = 10,
    ) -> None:
        self._client = client or build_default_client()
        self._base_url = base_url
        # EPSS covers 250,000+ CVEs; bounds a single sync call the same way
        # NVDConnector.max_pages does - adjustable, not a schema limitation.
        self._max_pages = max_pages

    def fetch(self, *, since: datetime | None = None) -> Iterator[RawIntelligenceRecord]:
        params: dict[str, str | int] = {"limit": _PAGE_LIMIT}
        if since is not None:
            params["date"] = since.date().isoformat()

        offset = 0
        for page in range(self._max_pages):
            body = fetch_json(self._client, self._base_url, params={**params, "offset": offset})
            if not isinstance(body, dict) or not isinstance(body.get("data"), list):
                raise ConnectorFetchError(
                    "EPSS response missing expected 'data' list - upstream schema may have changed"
                )

            items = body["data"]
            for entry in items:
                if not isinstance(entry, dict):
                    continue
                yield RawIntelligenceRecord(
                    source=self.source, external_id=str(entry.get("cve", "")), raw=entry
                )

            total = body.get("total", 0)
            offset += len(items)
            if len(items) == 0 or offset >= total:
                break

    def health(self) -> ConnectorHealth:
        try:
            fetch_json(self._client, self._base_url, params={"limit": 1}, max_retries=0)
        except ConnectorFetchError as exc:
            return ConnectorHealth(source=self.source, available=False, detail=str(exc))
        return ConnectorHealth(source=self.source, available=True, detail=None)
