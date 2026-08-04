"""Contract tests (SRS §11.1): every ProcessingStrategy must satisfy this interface uniformly."""

import re

import pytest

from zeroshield.strategies import ProcessingStrategy, StrategyOutcome
from zeroshield.strategies.telecom import (
    StrictGrammarStateMachineMitigation,
    WeakMandatoryFieldStateBaseline,
)
from zeroshield.strategies.vpn import (
    StrictSchemaCanonicalisationMitigation,
    WeakSchemaLengthBaseline,
)

ALL_STRATEGIES: list[ProcessingStrategy] = [
    WeakSchemaLengthBaseline(),
    StrictSchemaCanonicalisationMitigation(),
    WeakMandatoryFieldStateBaseline(),
    StrictGrammarStateMachineMitigation(),
]

STRATEGY_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

HOSTILE_INPUTS: list[dict] = [
    {},
    {"method": None},
    {"method": 123},
    {"headers": None},
    {"headers": "not-a-list"},
    {"headers": [None, 123, "not-a-pair", ["only-one-element"]]},
    {"sdp_attributes": None},
    {"sdp_attributes": "not-a-list"},
    {"query_params": None},
    {"query_params": "not-a-dict"},
    {"declared_content_length": None},
    {"declared_content_length": "not-a-number"},
    {"declared_body_length": None},
    {"sequence_number": None, "expected_sequence_number": None},
    {"session_state": None},
    {"path": None},
    {"encoding": None},
]


@pytest.mark.parametrize("strategy", ALL_STRATEGIES, ids=lambda s: s.strategy_id)
def test_strategy_id_matches_slug_pattern(strategy: ProcessingStrategy) -> None:
    assert STRATEGY_ID_PATTERN.match(strategy.strategy_id)


@pytest.mark.parametrize("strategy", ALL_STRATEGIES, ids=lambda s: s.strategy_id)
@pytest.mark.parametrize("hostile_input", HOSTILE_INPUTS, ids=lambda d: str(sorted(d.keys())))
def test_strategy_never_crashes_on_hostile_input(
    strategy: ProcessingStrategy, hostile_input: dict
) -> None:
    outcome = strategy.process(hostile_input)
    assert isinstance(outcome, StrategyOutcome)


@pytest.mark.parametrize("strategy", ALL_STRATEGIES, ids=lambda s: s.strategy_id)
def test_strategy_outcome_never_self_reports_errored(strategy: ProcessingStrategy) -> None:
    # errored=True is the runner's job on a caught exception (NFR-005), not a strategy's own call
    for hostile_input in HOSTILE_INPUTS:
        outcome = strategy.process(hostile_input)
        assert outcome.errored is False
