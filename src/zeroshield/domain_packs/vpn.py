"""VPNDomainPack - migrates the existing VPN capability (Milestones 1-30) into
the Domain Pack contract without rewriting the underlying, already-working
strategies (zeroshield.strategies.vpn.*)."""

from zeroshield.domain_packs.base import DomainPack
from zeroshield.models.enums import Domain, MetricName

VPN_DOMAIN_PACK = DomainPack(
    pack_id="vpn",
    name="VPN Domain Pack",
    version="1.0.0",
    domain=Domain.VPN,
    supported_failure_patterns=[
        "pre_auth_request_schema_validation",
        "pre_auth_path_canonicalisation",
        "pre_auth_length_boundary_enforcement",
    ],
    template_ids=["vpn_schema_canonicalisation"],
    allowed_strategy_ids=frozenset(
        {"weak_schema_length_baseline", "strict_schema_canonicalisation_mitigation"}
    ),
    dataset_generator_id="vpn_pre_auth_request_generator",
    domain_metrics=[
        MetricName.BLOCK_RATE,
        MetricName.VALID_ACCEPTANCE_RATE,
        MetricName.FALSE_POSITIVE_RATE,
        MetricName.FALSE_NEGATIVE_RATE,
        MetricName.PARSER_REACH_RATE,
        MetricName.MEAN_LATENCY_MS,
        MetricName.LOG_COMPLETENESS_RATE,
    ],
    compatibility={"min_core_version": "2.0.0"},
)
