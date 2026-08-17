"""Resolves a VulnerabilitySourceName to its connector instance - Factory
pattern, mirroring zeroshield.strategies.registry.resolve_strategy (a fixed
dict lookup, never dynamic import, so a source name can never load arbitrary
code). MANUAL_IMPORT has no connector (it is never fetched, only produced by
zeroshield.intelligence.excel_importer) and is deliberately excluded."""

from zeroshield.intelligence.connectors.base import ThreatIntelligenceConnector
from zeroshield.intelligence.connectors.cisa_kev import CISAKEVConnector
from zeroshield.intelligence.connectors.epss import EPSSConnector
from zeroshield.intelligence.connectors.github_advisory import GitHubAdvisoryConnector
from zeroshield.intelligence.connectors.nvd import NVDConnector
from zeroshield.models.vulnerability import VulnerabilitySourceName


class UnknownConnectorSourceError(Exception):
    pass


_REGISTRY: dict[VulnerabilitySourceName, type[ThreatIntelligenceConnector]] = {
    VulnerabilitySourceName.NVD: NVDConnector,
    VulnerabilitySourceName.CISA_KEV: CISAKEVConnector,
    VulnerabilitySourceName.EPSS: EPSSConnector,
    VulnerabilitySourceName.GITHUB_ADVISORY: GitHubAdvisoryConnector,
}


def build_connector(source: VulnerabilitySourceName) -> ThreatIntelligenceConnector:
    try:
        connector_cls = _REGISTRY[source]
    except KeyError:
        raise UnknownConnectorSourceError(
            f"no registered connector for source '{source.value}'; known sources: "
            f"{sorted(s.value for s in _REGISTRY)}"
        ) from None
    return connector_cls()


def known_sources() -> list[VulnerabilitySourceName]:
    return sorted(_REGISTRY, key=lambda s: s.value)
