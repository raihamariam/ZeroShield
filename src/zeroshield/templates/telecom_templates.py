"""Telecom validation templates - registered at import time. Configurable
parameters mirror the actual thresholds strict_grammar_state_machine_mitigation
already enforces (zeroshield.strategies.telecom.strict_mitigation).
"""

from zeroshield.models.enums import MetricName, SafetyLevel
from zeroshield.templates.models import ValidationTemplate
from zeroshield.templates.registry import register_template

TELECOM_GRAMMAR_STATE_MACHINE_V1 = ValidationTemplate(
    template_id="telecom_grammar_state_machine",
    version="1.0.0",
    domain_pack_id="telecom",
    name="Session-Setup Grammar & State-Machine Enforcement",
    supported_failure_patterns=[
        "session_setup_mandatory_field_validation",
        "session_setup_grammar_enforcement",
        "session_state_machine_enforcement",
    ],
    required_input_fields=["method", "session_state", "headers", "sequence_number", "expected_sequence_number"],
    allowed_baseline_strategies=["weak_mandatory_field_state_baseline"],
    allowed_mitigation_strategies=["strict_grammar_state_machine_mitigation"],
    configurable_parameters={
        "max_sdp_attr_value_length": 256,
        "max_body_length": 4096,
        "mandatory_headers": ["Call-ID", "From", "To"],
        "legal_transitions": [["INIT", "INVITE"], ["RINGING", "ACK"], ["ESTABLISHED", "BYE"]],
    },
    metrics_to_collect=[
        MetricName.BLOCK_RATE,
        MetricName.VALID_ACCEPTANCE_RATE,
        MetricName.FALSE_POSITIVE_RATE,
        MetricName.FALSE_NEGATIVE_RATE,
        MetricName.PARSER_REACH_RATE,
        MetricName.MEAN_LATENCY_MS,
        MetricName.LOG_COMPLETENESS_RATE,
    ],
    safety_level=SafetyLevel.SYNTHETIC_ONLY,
)

register_template(TELECOM_GRAMMAR_STATE_MACHINE_V1)
