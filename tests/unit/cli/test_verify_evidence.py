import json
from pathlib import Path

import pytest

from zeroshield.cli import main

REPO_ROOT = Path(__file__).resolve().parents[3]
VPN_EXPERIMENT = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"


def _real_run(results_dir: Path) -> None:
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


def test_verify_evidence_after_real_run_passes(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    results_dir = tmp_path / "results"
    _real_run(results_dir)
    capsys.readouterr()

    exit_code = main(["verify-evidence", str(results_dir / "ZC-VPN-EXP-001" / "RUN-002")])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "VERIFICATION: PASS" in out


def test_verify_evidence_detects_tampering(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    results_dir = tmp_path / "results"
    _real_run(results_dir)
    capsys.readouterr()

    manifest_path = results_dir / "ZC-VPN-EXP-001" / "RUN-002" / "manifest.json"
    tampered = manifest_path.read_text(encoding="utf-8").replace(
        "strict_schema_canonicalisation_mitigation", "weak_schema_length_baseline"
    )
    manifest_path.write_text(tampered, encoding="utf-8")

    exit_code = main(["verify-evidence", str(results_dir / "ZC-VPN-EXP-001" / "RUN-002")])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "VERIFICATION: FAIL" in out


def test_verify_evidence_missing_artefact_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    results_dir = tmp_path / "results"
    _real_run(results_dir)
    capsys.readouterr()

    (results_dir / "ZC-VPN-EXP-001" / "RUN-002" / "results.json").unlink()

    exit_code = main(["verify-evidence", str(results_dir / "ZC-VPN-EXP-001" / "RUN-002")])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Artefact files: FAIL" in out


def test_verify_evidence_missing_directory(tmp_path: Path) -> None:
    exit_code = main(["verify-evidence", str(tmp_path / "nope" / "RUN-999")])
    assert exit_code == 1


def test_verify_evidence_missing_manifest_file(tmp_path: Path) -> None:
    run_dir = tmp_path / "results" / "ZC-VPN-EXP-001" / "RUN-001"
    run_dir.mkdir(parents=True)
    exit_code = main(["verify-evidence", str(run_dir)])
    assert exit_code == 1


def test_verify_evidence_manifest_not_valid_json(tmp_path: Path) -> None:
    run_dir = tmp_path / "results" / "ZC-VPN-EXP-001" / "RUN-001"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text("{not valid json", encoding="utf-8")
    exit_code = main(["verify-evidence", str(run_dir)])
    assert exit_code == 1


def test_verify_evidence_manifest_fails_schema_validation(tmp_path: Path) -> None:
    run_dir = tmp_path / "results" / "ZC-VPN-EXP-001" / "RUN-001"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({"experiment_id": "ZC-VPN-EXP-001"}), encoding="utf-8"
    )
    exit_code = main(["verify-evidence", str(run_dir)])
    assert exit_code == 1


def test_verify_evidence_detects_run_id_directory_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    results_dir = tmp_path / "results"
    _real_run(results_dir)
    capsys.readouterr()

    real_dir = results_dir / "ZC-VPN-EXP-001" / "RUN-002"
    renamed_dir = results_dir / "ZC-VPN-EXP-001" / "RUN-999"
    real_dir.rename(renamed_dir)

    exit_code = main(["verify-evidence", str(renamed_dir)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Consistency: FAIL" in out
    assert "run_id" in out


def test_verify_evidence_detects_experiment_id_directory_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    results_dir = tmp_path / "results"
    _real_run(results_dir)
    capsys.readouterr()

    real_dir = results_dir / "ZC-VPN-EXP-001" / "RUN-002"
    renamed_experiment_dir = results_dir / "ZC-VPN-EXP-999"
    renamed_experiment_dir.mkdir()
    renamed_dir = renamed_experiment_dir / "RUN-002"
    real_dir.rename(renamed_dir)

    exit_code = main(["verify-evidence", str(renamed_dir)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Consistency: FAIL" in out
    assert "experiment_id" in out
