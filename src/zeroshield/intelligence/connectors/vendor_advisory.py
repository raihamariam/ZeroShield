"""Generic VendorAdvisoryConnector contract (Step 2).

A vendor/ecosystem advisory source differs from NVD/CISA/EPSS in one
structural way: its natural identifier is the *advisory's own* ID (e.g. a
GHSA id), not a CVE ID - an advisory may reference zero, one, or several
CVEs. Concrete implementations must therefore put the advisory's primary CVE
ID (or None) at `raw["cve_id"]`, which is the one contract
zeroshield.intelligence.normalisation relies on to link an advisory back to a
Vulnerability. `external_id` on the yielded RawIntelligenceRecord is always
the advisory ID, never the CVE ID.

Only implement a concrete vendor connector when reliable, documented,
programmatic access exists (Step 2: "do not add brittle scraping just to
claim coverage"). See zeroshield.intelligence.connectors.github_advisory for
the one concrete source implemented in V2 Phase 2, and the Phase 2 Completion
Report for why others (individual VPN/telecom vendor PSIRT pages) were not.
"""

from zeroshield.intelligence.connectors.base import ThreatIntelligenceConnector


class VendorAdvisoryConnector(ThreatIntelligenceConnector):
    """Marker base class documenting the vendor-advisory contract above -
    adds no new abstract methods over ThreatIntelligenceConnector."""
