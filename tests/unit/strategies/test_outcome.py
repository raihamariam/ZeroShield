import pytest
from pydantic import ValidationError

from zeroshield.strategies import StrategyOutcome


def test_valid_outcome_without_error() -> None:
    outcome = StrategyOutcome(decision="accepted", parser_reached=True)
    assert outcome.errored is False
    assert outcome.error_message is None


def test_valid_outcome_with_error() -> None:
    outcome = StrategyOutcome(
        decision="blocked", parser_reached=False, errored=True, error_message="boom"
    )
    assert outcome.errored is True


def test_errored_without_message_rejected() -> None:
    with pytest.raises(ValidationError, match="error_message is required"):
        StrategyOutcome(decision="blocked", parser_reached=False, errored=True)


def test_not_errored_with_message_rejected() -> None:
    with pytest.raises(ValidationError, match="must be None"):
        StrategyOutcome(
            decision="accepted", parser_reached=True, errored=False, error_message="oops"
        )


def test_outcome_is_immutable() -> None:
    outcome = StrategyOutcome(decision="accepted", parser_reached=True)
    with pytest.raises(ValidationError):
        outcome.decision = "blocked"
