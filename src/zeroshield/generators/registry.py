"""Resolves a generator_id to its DatasetGenerator instance - Factory pattern,
mirroring zeroshield.strategies.registry.resolve_strategy."""

from pydantic import BaseModel

from zeroshield.generators.base import DatasetGenerator
from zeroshield.generators.telecom_generator import TelecomDatasetGenerator, TelecomGeneratorConfig
from zeroshield.generators.vpn_generator import VPNDatasetGenerator, VPNGeneratorConfig


class UnknownGeneratorError(Exception):
    pass


_REGISTRY: dict[str, type[DatasetGenerator]] = {
    cls.generator_id: cls for cls in (VPNDatasetGenerator, TelecomDatasetGenerator)  # type: ignore[attr-defined]
}

_CONFIG_REGISTRY: dict[str, type[BaseModel]] = {
    VPNDatasetGenerator.generator_id: VPNGeneratorConfig,
    TelecomDatasetGenerator.generator_id: TelecomGeneratorConfig,
}


def resolve_generator(generator_id: str) -> DatasetGenerator:
    try:
        generator_cls = _REGISTRY[generator_id]
    except KeyError:
        raise UnknownGeneratorError(
            f"no registered generator for id '{generator_id}'; known generators: {sorted(_REGISTRY)}"
        ) from None
    return generator_cls()


def resolve_generator_config_cls(generator_id: str) -> type[BaseModel]:
    try:
        return _CONFIG_REGISTRY[generator_id]
    except KeyError:
        raise UnknownGeneratorError(
            f"no registered generator for id '{generator_id}'; known generators: {sorted(_REGISTRY)}"
        ) from None


def known_generator_ids() -> list[str]:
    return sorted(_REGISTRY)
