import pytest

from zeroshield.models.enums import SafetyLevel
from zeroshield.templates.models import ValidationTemplate
from zeroshield.templates.registry import (
    DuplicateTemplateError,
    UnknownTemplateError,
    latest_version,
    list_templates,
    register_template,
    resolve_template,
)


def _template(template_id: str, version: str) -> ValidationTemplate:
    return ValidationTemplate(
        template_id=template_id, version=version, domain_pack_id="vpn", name="test",
        supported_failure_patterns=["x"], required_input_fields=["method"],
        allowed_baseline_strategies=["weak_schema_length_baseline"],
        allowed_mitigation_strategies=["strict_schema_canonicalisation_mitigation"],
        metrics_to_collect=["block_rate"], safety_level=SafetyLevel.SYNTHETIC_ONLY,
    )


def test_resolve_registered_vpn_template() -> None:
    template = resolve_template("vpn_schema_canonicalisation", "1.0.0")
    assert template.domain_pack_id == "vpn"
    assert "weak_schema_length_baseline" in template.allowed_baseline_strategies


def test_resolve_registered_telecom_template() -> None:
    template = resolve_template("telecom_grammar_state_machine", "1.0.0")
    assert template.domain_pack_id == "telecom"


def test_resolve_unknown_template_raises() -> None:
    with pytest.raises(UnknownTemplateError):
        resolve_template("does_not_exist", "1.0.0")


def test_resolve_unknown_version_of_known_template_raises() -> None:
    with pytest.raises(UnknownTemplateError, match="known versions"):
        resolve_template("vpn_schema_canonicalisation", "99.0.0")


def test_list_templates_filters_by_domain_pack() -> None:
    vpn_templates = list_templates("vpn")
    assert all(t.domain_pack_id == "vpn" for t in vpn_templates)
    assert len(vpn_templates) >= 1


def test_register_duplicate_template_id_and_version_raises() -> None:
    with pytest.raises(DuplicateTemplateError):
        register_template(_template("vpn_schema_canonicalisation", "1.0.0"))


def test_historical_template_versions_remain_resolvable_after_new_version_registered() -> None:
    """Step 2: 'Historical experiments must keep their original template version.'
    Registering a new version must never remove or shadow an older one."""
    register_template(_template("vpn_test_versioning_template", "1.0.0"))
    register_template(_template("vpn_test_versioning_template", "1.1.0"))

    old = resolve_template("vpn_test_versioning_template", "1.0.0")
    new = resolve_template("vpn_test_versioning_template", "1.1.0")
    assert old.version == "1.0.0"
    assert new.version == "1.1.0"
    assert latest_version("vpn_test_versioning_template").version == "1.1.0"
