import json
from pathlib import Path

import pytest

from zeroshield.cli import main
from zeroshield.cli.commands import validate_experiment
from zeroshield.policies import ExecutionContext

REPO_ROOT = Path(__file__).resolve().parents[3]
VPN_EXPERIMENT = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"


def test_validate_experiment_passes_under_local_unit_test_context() -> None:
    ok = validate_experiment(VPN_EXPERIMENT, context=ExecutionContext.LOCAL_UNIT_TEST)
    assert ok is True


def test_validate_experiment_fails_under_default_context_for_draft_experiment() -> None:
    # SAFE-004: real experiment is still draft, so the strict default context refuses it.
    ok = validate_experiment(VPN_EXPERIMENT, context=ExecutionContext.EXPERIMENT_RUN)
    assert ok is False


def test_cli_validate_experiment_exit_code_zero(capsys: pytest.CaptureFixture) -> None:
    exit_code = main(["validate-experiment", str(VPN_EXPERIMENT), "--context", "local_unit_test"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "VALIDATION: PASS" in out


def test_cli_validate_experiment_default_context_nonzero_exit(capsys: pytest.CaptureFixture) -> None:
    exit_code = main(["validate-experiment", str(VPN_EXPERIMENT)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "VALIDATION: FAIL" in out
    assert "SAFE-004" in out


def test_cli_validate_experiment_rejects_malformed_json(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json", encoding="utf-8")
    exit_code = main(["validate-experiment", str(bad_file)])
    assert exit_code == 1


def test_cli_validate_experiment_rejects_schema_invalid(tmp_path: Path) -> None:
    bad_file = tmp_path / "invalid.json"
    bad_file.write_text(json.dumps({"experiment_id": "not-a-valid-id"}), encoding="utf-8")
    exit_code = main(["validate-experiment", str(bad_file)])
    assert exit_code == 1


def test_cli_validate_experiment_missing_file(tmp_path: Path) -> None:
    exit_code = main(["validate-experiment", str(tmp_path / "does_not_exist.json")])
    assert exit_code == 1


def test_cli_validate_experiment_missing_dataset(tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT.read_text(encoding="utf-8"))
    data["dataset_path"] = "test_data/vpn/does_not_exist.json"
    bad_file = tmp_path / "missing_dataset.json"
    bad_file.write_text(json.dumps(data), encoding="utf-8")
    exit_code = main(["validate-experiment", str(bad_file), "--context", "local_unit_test"])
    assert exit_code == 1
