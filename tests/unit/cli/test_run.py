import json
from pathlib import Path

import pytest

from zeroshield.cli import main
from zeroshield.models import ApprovalStatus

REPO_ROOT = Path(__file__).resolve().parents[3]
VPN_EXPERIMENT = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"
TELECOM_EXPERIMENT = REPO_ROOT / "experiments" / "ZC-TELECOM-EXP-001.json"


def test_run_vpn_experiment_succeeds_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Integration-level: invokes the real orchestration/runner/strategies, no mocking."""
    results_dir = tmp_path / "results"
    exit_code = main(
        [
            "run",
            str(VPN_EXPERIMENT),
            "--context",
            "local_unit_test",
            "--results-dir",
            str(results_dir),
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "ZC-VPN-EXP-001" in out
    assert "COMPLETION: SUCCESS" in out
    assert (results_dir / "ZC-VPN-EXP-001").is_dir()
    manifests = list((results_dir / "ZC-VPN-EXP-001").glob("*/manifest.json"))
    assert len(manifests) == 2


def test_run_telecom_experiment_succeeds_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    results_dir = tmp_path / "results"
    exit_code = main(
        [
            "run",
            str(TELECOM_EXPERIMENT),
            "--context",
            "local_unit_test",
            "--results-dir",
            str(results_dir),
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "ZC-TELECOM-EXP-001" in out
    assert "COMPLETION: SUCCESS" in out


def test_run_denied_by_safety_policy_before_execution_for_draft_experiment(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    # ZC-VPN-EXP-001 is still draft; default --context is the strict experiment_run.
    results_dir = tmp_path / "results"
    exit_code = main(["run", str(VPN_EXPERIMENT), "--results-dir", str(results_dir)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "DENIED" in out
    assert "SAFE-004" in out
    # strongest proof: the runner never executed, so no evidence was ever written
    assert not results_dir.exists()


def test_run_denied_for_unsafe_configured_experiment_even_if_approved(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    data = json.loads(VPN_EXPERIMENT.read_text(encoding="utf-8"))
    data["external_targeting"] = True
    data["approval_status"] = ApprovalStatus.APPROVED.value
    unsafe_file = tmp_path / "unsafe.json"
    unsafe_file.write_text(json.dumps(data), encoding="utf-8")

    results_dir = tmp_path / "results"
    exit_code = main(["run", str(unsafe_file), "--results-dir", str(results_dir)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "DENIED" in out
    assert "SAFE-001" in out
    assert not results_dir.exists()


def test_run_unknown_strategy_identifier_rejected(tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT.read_text(encoding="utf-8"))
    data["baseline_strategy"] = "totally_unknown_strategy"
    bad_file = tmp_path / "bad_strategy.json"
    bad_file.write_text(json.dumps(data), encoding="utf-8")

    results_dir = tmp_path / "results"
    exit_code = main(
        [
            "run",
            str(bad_file),
            "--context",
            "local_unit_test",
            "--results-dir",
            str(results_dir),
        ]
    )
    assert exit_code == 1
    assert not results_dir.exists()


def test_run_missing_experiment_file(tmp_path: Path) -> None:
    exit_code = main(
        ["run", str(tmp_path / "nope.json"), "--results-dir", str(tmp_path / "results")]
    )
    assert exit_code == 1


def test_run_missing_dataset_file(tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT.read_text(encoding="utf-8"))
    data["dataset_path"] = "test_data/vpn/does_not_exist.json"
    bad_file = tmp_path / "missing_dataset.json"
    bad_file.write_text(json.dumps(data), encoding="utf-8")

    exit_code = main(
        [
            "run",
            str(bad_file),
            "--context",
            "local_unit_test",
            "--results-dir",
            str(tmp_path / "results"),
        ]
    )
    assert exit_code == 1


def test_run_accepts_explicit_run_ids(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    results_dir = tmp_path / "results"
    exit_code = main(
        [
            "run",
            str(VPN_EXPERIMENT),
            "--context",
            "local_unit_test",
            "--results-dir",
            str(results_dir),
            "--baseline-run-id",
            "RUN-001",
            "--mitigation-run-id",
            "RUN-002",
        ]
    )
    assert exit_code == 0
    assert (results_dir / "ZC-VPN-EXP-001" / "RUN-001" / "manifest.json").is_file()
    assert (results_dir / "ZC-VPN-EXP-001" / "RUN-002" / "manifest.json").is_file()
