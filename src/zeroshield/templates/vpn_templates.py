"""VPN validation templates - registered at import time. Configurable
parameters mirror the actual thresholds strict_schema_canonicalisation_mitigation
already enforces (zeroshield.strategies.vpn.strict_mitigation), so a template
consumer can see/tune exactly what the mitigation checks, without touching
the strategy code itself.
"""

from zeroshield.models.enums import MetricName, SafetyLevel
from zeroshield.templates.models import ValidationTemplate
from zeroshield.templates.registry import register_template

VPN_SCHEMA_CANONICALISATION_V1 = ValidationTemplate(
    template_id="vpn_schema_canonicalisation",
    version="1.0.0",
    domain_pack_id="vpn",
    name="Pre-Auth Request Schema Validation & Canonicalisation",
    supported_failure_patterns=[
        "pre_auth_request_schema_validation",
        "pre_auth_path_canonicalisation",
        "pre_auth_length_boundary_enforcement",
    ],
    required_input_fields=["method", "path", "declared_content_length", "actual_body_length", "encoding"],
    allowed_baseline_strategies=["weak_schema_length_baseline"],
    allowed_mitigation_strategies=["strict_schema_canonicalisation_mitigation"],
    configurable_parameters={
        "max_path_length": 256,
        "max_body_length": 8192,
        "max_header_value_length": 512,
        "max_query_param_value_length": 512,
        "allowed_encodings": ["utf-8", "ascii"],
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

register_template(VPN_SCHEMA_CANONICALISATION_V1)
