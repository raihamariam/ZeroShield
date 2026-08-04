from pathlib import Path

from zeroshield.api import dependencies


def test_get_experiments_dir_defaults_to_cwd_experiments() -> None:
    assert dependencies.get_experiments_dir() == Path.cwd() / "experiments"


def test_get_results_root_defaults_to_cwd_results() -> None:
    assert dependencies.get_results_root() == Path.cwd() / "results"
