"""TelecomDomainPack - migrates the existing Telecom capability (Milestones
1-30) into the Domain Pack contract without rewriting the underlying,
already-working strategies (zeroshield.strategies.telecom.*)."""

from zeroshield.domain_packs.base import DomainPack
from zeroshield.models.enums import Domain, MetricName

TELECOM_DOMAIN_PACK = DomainPack(
    pack_id="telecom",
    name="Telecom Domain Pack",
    version="1.0.0",
    domain=Domain.TELECOM,
    supported_failure_patterns=[
        "session_setup_mandatory_field_validation",
        "session_setup_grammar_enforcement",
        "session_state_machine_enforcement",
    ],
    template_ids=["telecom_grammar_state_machine"],
    allowed_strategy_ids=frozenset(
        {"weak_mandatory_field_state_baseline", "strict_grammar_state_machine_mitigation"}
    ),
    dataset_generator_id="telecom_sip_session_setup_generator",
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
