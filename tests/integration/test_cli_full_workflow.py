"""End-to-end CLI workflow: validate -> run -> compare -> verify-evidence, invoked
as real subprocesses against the installed `zeroshield` console script - not
in-process main() calls like tests/unit/cli/ uses. This is the actual sequence
a researcher would type at a terminal, exercised through the real interface
boundary (a separate OS process, real argv parsing, real stdout).

Happy path only: denial/failure-path scenarios are Milestone 26's scope.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "zeroshield", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _full_workflow(experiment_id: str, expected_cases: int, tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    experiment_path = REPO_ROOT / "experiments" / f"{experiment_id}.json"

    validate = _run_cli(
        "validate-experiment", str(experiment_path), "--context", "local_unit_test", cwd=REPO_ROOT
    )
    assert validate.returncode == 0, validate.stdout + validate.stderr
    assert "VALIDATION: PASS" in validate.stdout

    run = _run_cli(
        "run",
        str(experiment_path),
        "--context",
        "local_unit_test",
        "--results-dir",
        str(results_dir),
        "--baseline-run-id",
        "RUN-001",
        "--mitigation-run-id",
        "RUN-002",
        cwd=REPO_ROOT,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "COMPLETION: SUCCESS" in run.stdout
    assert f"Cases: {expected_cases}" in run.stdout

    experiment_dir = results_dir / experiment_id
    assert (experiment_dir / "comparison.json").is_file()
    assert (experiment_dir / "RUN-001" / "manifest.json").is_file()
    assert (experiment_dir / "RUN-002" / "manifest.json").is_file()

    compare = _run_cli("compare", str(experiment_dir), cwd=REPO_ROOT)
    assert compare.returncode == 0, compare.stdout + compare.stderr
    assert experiment_id in compare.stdout
    assert "block_rate" in compare.stdout
    assert "Limitations" in compare.stdout

    for run_id in ("RUN-001", "RUN-002"):
        verify = _run_cli("verify-evidence", str(experiment_dir / run_id), cwd=REPO_ROOT)
        assert verify.returncode == 0, verify.stdout + verify.stderr
        assert "VERIFICATION: PASS" in verify.stdout


def test_full_cli_workflow_vpn(tmp_path: Path) -> None:
    _full_workflow("ZC-VPN-EXP-001", 22, tmp_path)


def test_full_cli_workflow_telecom(tmp_path: Path) -> None:
    _full_workflow("ZC-TELECOM-EXP-001", 25, tmp_path)
