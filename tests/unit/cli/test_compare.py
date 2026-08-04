from pathlib import Path

import pytest

from zeroshield.cli import main

REPO_ROOT = Path(__file__).resolve().parents[3]
VPN_EXPERIMENT = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"


def test_compare_after_real_run(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    results_dir = tmp_path / "results"
    run_exit = main(
        [
            "run",
            str(VPN_EXPERIMENT),
            "--context",
            "local_unit_test",
            "--results-dir",
            str(results_dir),
        ]
    )
    assert run_exit == 0
    capsys.readouterr()

    compare_exit = main(["compare", str(results_dir / "ZC-VPN-EXP-001")])
    assert compare_exit == 0
    out = capsys.readouterr().out
    assert "ZC-VPN-EXP-001" in out
    assert "block_rate" in out
    assert "Limitations" in out


def test_compare_missing_comparison_file(tmp_path: Path) -> None:
    exit_code = main(["compare", str(tmp_path)])
    assert exit_code == 1


def test_compare_missing_directory(tmp_path: Path) -> None:
    exit_code = main(["compare", str(tmp_path / "does_not_exist")])
    assert exit_code == 1


def test_compare_rejects_malformed_comparison_json(tmp_path: Path) -> None:
    (tmp_path / "comparison.json").write_text("{not valid json", encoding="utf-8")
    exit_code = main(["compare", str(tmp_path)])
    assert exit_code == 1
