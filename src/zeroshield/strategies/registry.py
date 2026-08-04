from zeroshield.strategies.base import ProcessingStrategy
from zeroshield.strategies.telecom import (
    StrictGrammarStateMachineMitigation,
    WeakMandatoryFieldStateBaseline,
)
from zeroshield.strategies.vpn import (
    StrictSchemaCanonicalisationMitigation,
    WeakSchemaLengthBaseline,
)


class UnknownStrategyError(Exception):
    """Raised when a strategy_id has no registered implementation, per SRS §4.2 Factory pattern."""


_REGISTRY: dict[str, type[ProcessingStrategy]] = {
    cls.strategy_id: cls
    for cls in (
        WeakSchemaLengthBaseline,
        StrictSchemaCanonicalisationMitigation,
        WeakMandatoryFieldStateBaseline,
        StrictGrammarStateMachineMitigation,
    )
}


def resolve_strategy(strategy_id: str) -> ProcessingStrategy:
    try:
        strategy_cls = _REGISTRY[strategy_id]
    except KeyError:
        raise UnknownStrategyError(
            f"no registered strategy for identifier '{strategy_id}'; known identifiers: "
            f"{sorted(_REGISTRY)}"
        ) from None
    return strategy_cls()


def known_strategy_ids() -> list[str]:
    return sorted(_REGISTRY)
