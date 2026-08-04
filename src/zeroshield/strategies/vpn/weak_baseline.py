from typing import Any

from zeroshield.models.enums import Decision
from zeroshield.strategies.base import ProcessingStrategy
from zeroshield.strategies.outcome import StrategyOutcome


class WeakSchemaLengthBaseline(ProcessingStrategy):
    """Deliberately weak pre-auth VPN baseline (method/path presence only), per SRS §6.1."""

    strategy_id = "weak_schema_length_baseline"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        method = input_data.get("method")
        if not isinstance(method, str) or not method:
            return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False)

        path = input_data.get("path")
        if not isinstance(path, str) or not path:
            return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False)

        return StrategyOutcome(decision=Decision.ACCEPTED, parser_reached=True)
