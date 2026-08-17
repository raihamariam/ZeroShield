"""Resolves a domain-pack id to its DomainPack descriptor - Factory pattern,
mirroring zeroshield.strategies.registry.resolve_strategy: a fixed dict, never
dynamic import, so an unknown/attacker-controlled pack_id can never load
arbitrary code."""

from zeroshield.domain_packs.base import DomainPack
from zeroshield.domain_packs.telecom import TELECOM_DOMAIN_PACK
from zeroshield.domain_packs.vpn import VPN_DOMAIN_PACK


class UnknownDomainPackError(Exception):
    pass


_REGISTRY: dict[str, DomainPack] = {
    VPN_DOMAIN_PACK.pack_id: VPN_DOMAIN_PACK,
    TELECOM_DOMAIN_PACK.pack_id: TELECOM_DOMAIN_PACK,
}


def resolve_domain_pack(pack_id: str) -> DomainPack:
    try:
        return _REGISTRY[pack_id]
    except KeyError:
        raise UnknownDomainPackError(
            f"no registered domain pack for id '{pack_id}'; known packs: {sorted(_REGISTRY)}"
        ) from None


def known_domain_packs() -> list[DomainPack]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]
