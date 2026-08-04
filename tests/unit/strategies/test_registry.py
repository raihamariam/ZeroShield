import pytest

from zeroshield.strategies import ProcessingStrategy
from zeroshield.strategies.registry import (
    UnknownStrategyError,
    known_strategy_ids,
    resolve_strategy,
)
from zeroshield.strategies.telecom import (
    StrictGrammarStateMachineMitigation,
    WeakMandatoryFieldStateBaseline,
)
from zeroshield.strategies.vpn import (
    StrictSchemaCanonicalisationMitigation,
    WeakSchemaLengthBaseline,
)


def test_resolve_strategy_returns_correct_instance_for_all_known_ids() -> None:
    expectations = {
        "weak_schema_length_baseline": WeakSchemaLengthBaseline,
        "strict_schema_canonicalisation_mitigation": StrictSchemaCanonicalisationMitigation,
        "weak_mandatory_field_state_baseline": WeakMandatoryFieldStateBaseline,
        "strict_grammar_state_machine_mitigation": StrictGrammarStateMachineMitigation,
    }
    for strategy_id, expected_cls in expectations.items():
        strategy = resolve_strategy(strategy_id)
        assert isinstance(strategy, expected_cls)
        assert isinstance(strategy, ProcessingStrategy)
        assert strategy.strategy_id == strategy_id


def test_resolve_strategy_returns_fresh_instance_each_call() -> None:
    a = resolve_strategy("weak_schema_length_baseline")
    b = resolve_strategy("weak_schema_length_baseline")
    assert a is not b


def test_resolve_unknown_strategy_raises() -> None:
    with pytest.raises(UnknownStrategyError, match="unknown_strategy_xyz"):
        resolve_strategy("unknown_strategy_xyz")


def test_known_strategy_ids_lists_all_four_sorted() -> None:
    ids = known_strategy_ids()
    assert ids == sorted(ids)
    assert set(ids) == {
        "weak_schema_length_baseline",
        "strict_schema_canonicalisation_mitigation",
        "weak_mandatory_field_state_baseline",
        "strict_grammar_state_machine_mitigation",
    }
