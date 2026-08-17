"""Threat Intelligence & Prioritisation (V2 Phase 2).

Converts vulnerability intelligence from official/reliable sources (NVD, CISA
KEV, FIRST EPSS, selected vendor advisories) into ZeroShield's own normalised,
deduplicated, historized Vulnerability records, then produces an explainable,
deterministic ZeroShield Validation Priority and VPN/Telecom ValidationCandidate
records. No AI is used anywhere in this package - see zeroshield.intelligence.priority
for the deterministic scoring rules.
"""
