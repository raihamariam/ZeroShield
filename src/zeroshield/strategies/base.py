from abc import ABC, abstractmethod
from typing import Any

from zeroshield.strategies.outcome import StrategyOutcome


class ProcessingStrategy(ABC):
    """Common interface for baseline/mitigation strategies, per SRS §4.2 Strategy pattern."""

    strategy_id: str

    @abstractmethod
    def process(self, input_data: dict[str, Any]) -> StrategyOutcome: ...
