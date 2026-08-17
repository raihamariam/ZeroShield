"""CISA Known Exploited Vulnerabilities (KEV) catalog connector.

Schema grounded in the official feed read at implementation time
(https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json,
via https://www.cisa.gov/known-exploited-vulnerabilities-catalog - August 2026):

- No authentication, no pagination - it is a single bulk JSON snapshot of the
  whole catalog, updated multiple times per week.
- Top level: {"title", "catalogVersion", "dateReleased", "count", "vulnerabilities": [...]}
- Each entry: {cveID, vendorProject, product, vulnerabilityName, dateAdded,
  shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes,
  cwes[]}

Since the catalog has no server-side incremental filter, `since` is applied
client-side against `dateAdded` (a CVE only enters the catalog once, so this
is a correct - if coarser than NVD's lastModified-based one - notion of
"new since").
"""

from collections.abc import Iterator
from datetime import date, datetime

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

_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVConnector(ThreatIntelligenceConnector):
    source = VulnerabilitySourceName.CISA_KEV

    def __init__(self, *, client: httpx.Client | None = None, catalog_url: str = _CATALOG_URL) -> None:
        self._client = client or build_default_client()
        self._catalog_url = catalog_url

    def fetch(self, *, since: datetime | None = None) -> Iterator[RawIntelligenceRecord]:
        body = fetch_json(self._client, self._catalog_url)
        if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
            raise ConnectorFetchError(
                "CISA KEV response missing expected 'vulnerabilities' list - upstream schema may "
                "have changed"
            )

        since_date = since.date() if since is not None else None
        for entry in body["vulnerabilities"]:
            if not isinstance(entry, dict):
                continue
            if since_date is not None:
                added = _parse_iso_date(entry.get("dateAdded"))
                if added is not None and added < since_date:
                    continue
            yield RawIntelligenceRecord(
                source=self.source, external_id=str(entry.get("cveID", "")), raw=entry
            )

    def health(self) -> ConnectorHealth:
        try:
            body = fetch_json(self._client, self._catalog_url, max_retries=0)
        except ConnectorFetchError as exc:
            return ConnectorHealth(source=self.source, available=False, detail=str(exc))
        if not isinstance(body, dict) or "vulnerabilities" not in body:
            return ConnectorHealth(
                source=self.source, available=False, detail="response missing 'vulnerabilities' key"
            )
        return ConnectorHealth(source=self.source, available=True, detail=None)


def _parse_iso_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None
