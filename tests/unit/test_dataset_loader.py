import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from zeroshield.datasets import load_test_set

VALID_DATASET = {
    "test_set_id": "sample-v1",
    "version": "1.0.0",
    "domain": "VPN",
    "cases": [
        {
            "case_id": "TC-001",
            "category": "valid",
            "input_data": {"method": "GET", "path": "/remote/login"},
            "expected_outcome": "accepted",
            "provenance": "synthetic",
            "version": "1.0.0",
        }
    ],
}


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_load_valid_dataset_returns_test_set_and_hash(tmp_path: Path) -> None:
    file_path = _write(tmp_path / "dataset.json", json.dumps(VALID_DATASET))
    test_set, sha256_hex = load_test_set(file_path)
    assert test_set.test_set_id == "sample-v1"
    assert len(test_set.cases) == 1
    assert sha256_hex == hashlib.sha256(file_path.read_bytes()).hexdigest()
    assert len(sha256_hex) == 64


def test_load_is_deterministic(tmp_path: Path) -> None:
    file_path = _write(tmp_path / "dataset.json", json.dumps(VALID_DATASET))
    _, hash_one = load_test_set(file_path)
    _, hash_two = load_test_set(file_path)
    assert hash_one == hash_two


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_test_set(tmp_path / "does_not_exist.json")


def test_load_malformed_json_raises(tmp_path: Path) -> None:
    file_path = _write(tmp_path / "dataset.json", "{not valid json")
    with pytest.raises(json.JSONDecodeError):
        load_test_set(file_path)


def test_load_structurally_invalid_dataset_raises(tmp_path: Path) -> None:
    invalid = {**VALID_DATASET, "cases": []}
    file_path = _write(tmp_path / "dataset.json", json.dumps(invalid))
    with pytest.raises(ValidationError):
        load_test_set(file_path)
