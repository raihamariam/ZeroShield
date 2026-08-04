from pathlib import Path

from zeroshield.experiments import discover_experiments

REPO_ROOT = Path(__file__).resolve().parents[3]
REAL_EXPERIMENTS_DIR = REPO_ROOT / "experiments"


def test_discover_experiments_finds_real_vpn_and_telecom_experiments() -> None:
    result = discover_experiments(REAL_EXPERIMENTS_DIR)
    ids = {e.experiment_id for e in result.experiments}
    assert "ZC-VPN-EXP-001" in ids
    assert "ZC-TELECOM-EXP-001" in ids
    assert result.skipped == []


def test_discover_experiments_is_sorted_deterministically() -> None:
    result = discover_experiments(REAL_EXPERIMENTS_DIR)
    ids = [e.experiment_id for e in result.experiments]
    assert ids == sorted(ids)


def test_discover_experiments_skips_invalid_json_with_reason(tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text("{not valid json", encoding="utf-8")
    result = discover_experiments(tmp_path)
    assert result.experiments == []
    assert len(result.skipped) == 1
    assert result.skipped[0].path.name == "broken.json"
    assert "invalid JSON" in result.skipped[0].reason


def test_discover_experiments_skips_schema_invalid_with_reason(tmp_path: Path) -> None:
    (tmp_path / "incomplete.json").write_text('{"experiment_id": "ZC-VPN-EXP-999"}', encoding="utf-8")
    result = discover_experiments(tmp_path)
    assert result.experiments == []
    assert len(result.skipped) == 1
    assert "schema validation failed" in result.skipped[0].reason


def test_discover_experiments_mixed_valid_and_invalid(tmp_path: Path) -> None:
    valid_raw = (REAL_EXPERIMENTS_DIR / "ZC-VPN-EXP-001.json").read_text(encoding="utf-8")
    (tmp_path / "ZC-VPN-EXP-001.json").write_text(valid_raw, encoding="utf-8")
    (tmp_path / "not_an_experiment.json").write_text("{}", encoding="utf-8")

    result = discover_experiments(tmp_path)
    assert [e.experiment_id for e in result.experiments] == ["ZC-VPN-EXP-001"]
    assert len(result.skipped) == 1


def test_discover_experiments_missing_directory_returns_empty(tmp_path: Path) -> None:
    result = discover_experiments(tmp_path / "does_not_exist")
    assert result.experiments == []
    assert result.skipped == []


def test_discover_experiments_ignores_non_json_files(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    result = discover_experiments(tmp_path)
    assert result.experiments == []
    assert result.skipped == []
