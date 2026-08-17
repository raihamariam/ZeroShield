import pytest

from zeroshield.intelligence.connectors.cisa_kev import CISAKEVConnector
from zeroshield.intelligence.connectors.epss import EPSSConnector
from zeroshield.intelligence.connectors.github_advisory import GitHubAdvisoryConnector
from zeroshield.intelligence.connectors.nvd import NVDConnector
from zeroshield.intelligence.connectors.registry import (
    UnknownConnectorSourceError,
    build_connector,
    known_sources,
)
from zeroshield.models.vulnerability import VulnerabilitySourceName


@pytest.mark.parametrize(
    ("source", "expected_cls"),
    [
        (VulnerabilitySourceName.NVD, NVDConnector),
        (VulnerabilitySourceName.CISA_KEV, CISAKEVConnector),
        (VulnerabilitySourceName.EPSS, EPSSConnector),
        (VulnerabilitySourceName.GITHUB_ADVISORY, GitHubAdvisoryConnector),
    ],
)
def test_build_connector_resolves_correct_class(source, expected_cls) -> None:
    connector = build_connector(source)
    assert isinstance(connector, expected_cls)
    assert connector.source is source


def test_build_connector_unknown_source_raises() -> None:
    with pytest.raises(UnknownConnectorSourceError):
        build_connector(VulnerabilitySourceName.MANUAL_IMPORT)


def test_known_sources_excludes_manual_import() -> None:
    sources = known_sources()
    assert VulnerabilitySourceName.MANUAL_IMPORT not in sources
    assert VulnerabilitySourceName.NVD in sources
    assert sources == sorted(sources, key=lambda s: s.value)
