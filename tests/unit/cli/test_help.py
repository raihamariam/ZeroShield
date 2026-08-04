import pytest

from zeroshield.cli import main


def test_help_exits_zero_and_lists_all_commands(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "validate-experiment" in out
    assert "run" in out
    assert "compare" in out
    assert "verify-evidence" in out


def test_no_command_exits_nonzero() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code != 0


def test_subcommand_help_exits_zero(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["run", "--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "--context" in out
