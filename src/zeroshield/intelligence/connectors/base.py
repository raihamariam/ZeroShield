"""Common ThreatIntelligenceConnector abstraction (Step 2). Business code
(zeroshield.intelligence.sync_service, normalisation, the sync worker) depends
only on this interface, never on any external API's own schema - each concrete
connector is the sole place that knows NVD/CISA/EPSS/GitHub's actual response
shape, matching the Repository/Strategy pattern already used throughout this
codebase (EvidenceRepository, ProcessingStrategy)."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from zeroshield.models.vulnerability import VulnerabilitySourceName


@dataclass(frozen=True)
class RawIntelligenceRecord:
    """One upstream item, minimally typed - `raw` is exactly what the source
    returned for this record (already JSON-decoded, size/shape-validated at
    the transport level by connectors.http.fetch_json, but its *field values*
    are still untrusted). Normalisation (zeroshield.intelligence.normalisation)
    is the only place that reaches into `raw` and validates individual fields."""

    source: VulnerabilitySourceName
    external_id: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class ConnectorHealth:
    source: VulnerabilitySourceName
    available: bool
    detail: str | None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class ThreatIntelligenceConnector(ABC):
    """One implementation per source. `source` is the connector's identity
    (Step 2: "source identity"); `fetch` and `health` are its only two
    required behaviours (Step 2: "fetch/update... and health semantics").
    Normalisation is deliberately NOT part of this interface - see
    zeroshield.intelligence.normalisation, which maps every connector's
    RawIntelligenceRecord stream to the same internal shape uniformly."""

    source: VulnerabilitySourceName

    @abstractmethod
    def fetch(self, *, since: datetime | None = None) -> Iterator[RawIntelligenceRecord]:
        """Yields every record available (since=None) or modified/added since
        the given timestamp (incremental sync). Raises
        zeroshield.intelligence.connectors.http.ConnectorFetchError on a
        whole-fetch failure (network/transport/shape) - never silently
        returns partial-but-unflagged data for a total failure."""

    @abstractmethod
    def health(self) -> ConnectorHealth:
        """A cheap reachability check - must never raise; failures are
        reported via ConnectorHealth(available=False, detail=...)."""
