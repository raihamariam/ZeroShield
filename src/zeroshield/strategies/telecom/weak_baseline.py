from typing import Any

from zeroshield.models.enums import Decision
from zeroshield.strategies.base import ProcessingStrategy
from zeroshield.strategies.outcome import StrategyOutcome

KNOWN_METHODS = {"INVITE", "ACK", "BYE"}
KNOWN_STATES = {"INIT", "RINGING", "ESTABLISHED", "TERMINATED"}


class WeakMandatoryFieldStateBaseline(ProcessingStrategy):
    """Deliberately weak Telecom session-setup baseline (superficial field/state presence only), per SRS §6.2."""

    strategy_id = "weak_mandatory_field_state_baseline"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        method = input_data.get("method")
        if not isinstance(method, str) or method not in KNOWN_METHODS:
            return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False)

        headers = input_data.get("headers")
        if not isinstance(headers, list) or not headers:
            return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False)

        session_state = input_data.get("session_state")
        if not isinstance(session_state, str) or session_state not in KNOWN_STATES:
            return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False)

        return StrategyOutcome(decision=Decision.ACCEPTED, parser_reached=True)
