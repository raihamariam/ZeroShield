import pytest

from zeroshield.strategies import ProcessingStrategy


def test_processing_strategy_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError):
        ProcessingStrategy()  # type: ignore[abstract]
