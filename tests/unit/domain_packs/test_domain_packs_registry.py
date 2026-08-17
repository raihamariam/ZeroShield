import pytest

from zeroshield.domain_packs import UnknownDomainPackError, known_domain_packs, resolve_domain_pack
from zeroshield.models.enums import Domain


def test_known_domain_packs_includes_vpn_and_telecom() -> None:
    ids = [p.pack_id for p in known_domain_packs()]
    assert ids == sorted(ids)
    assert "vpn" in ids
    assert "telecom" in ids


def test_resolve_vpn_domain_pack() -> None:
    pack = resolve_domain_pack("vpn")
    assert pack.domain is Domain.VPN
    assert pack.allowed_strategy_ids == frozenset(
        {"weak_schema_length_baseline", "strict_schema_canonicalisation_mitigation"}
    )
    assert "vpn_schema_canonicalisation" in pack.template_ids


def test_resolve_telecom_domain_pack() -> None:
    pack = resolve_domain_pack("telecom")
    assert pack.domain is Domain.TELECOM
    assert pack.allowed_strategy_ids == frozenset(
        {"weak_mandatory_field_state_baseline", "strict_grammar_state_machine_mitigation"}
    )


def test_resolve_unknown_domain_pack_raises() -> None:
    with pytest.raises(UnknownDomainPackError, match="no registered domain pack"):
        resolve_domain_pack("does_not_exist")


def test_domain_pack_allowed_strategies_never_cross_domains() -> None:
    """A domain pack's allow-list must never include a strategy belonging to
    another domain - the whole point of the pack-scoped allow-list on top of
    the global strategy registry."""
    vpn = resolve_domain_pack("vpn")
    telecom = resolve_domain_pack("telecom")
    assert vpn.allowed_strategy_ids.isdisjoint(telecom.allowed_strategy_ids)
