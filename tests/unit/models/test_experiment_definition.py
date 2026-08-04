import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from zeroshield.models import ApprovalStatus, ExperimentDefinition

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "experiments"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_valid_experiment_definition_parses_from_fixture() -> None:
    data = _load_fixture("valid_experiment_example.json")
    experiment = ExperimentDefinition(**data)
    assert experiment.experiment_id == "ZC-VPN-EXP-999"
    assert experiment.domain.value == "VPN"
    assert experiment.approval_status == ApprovalStatus.DRAFT
    assert experiment.version == "1.0.0"
    assert len(experiment.related_cves) == 1


def test_invalid_experiment_definition_fixture_reports_field_errors() -> None:
    data = _load_fixture("invalid_experiment_example.json")
    with pytest.raises(ValidationError) as exc_info:
        ExperimentDefinition(**data)
    error_fields = {error["loc"][0] for error in exc_info.value.errors()}
    assert "title" in error_fields
    assert "related_cves" in error_fields
    assert "dataset_path" in error_fields
    assert "metrics_to_collect" in error_fields


def test_experiment_id_domain_mismatch_rejected(valid_experiment_definition_data: dict) -> None:
    valid_experiment_definition_data["domain"] = "TELECOM"
    with pytest.raises(ValidationError, match="domain segment"):
        ExperimentDefinition(**valid_experiment_definition_data)


def test_baseline_and_mitigation_must_differ(valid_experiment_definition_data: dict) -> None:
    valid_experiment_definition_data["mitigation_strategy"] = valid_experiment_definition_data[
        "baseline_strategy"
    ]
    with pytest.raises(ValidationError, match="must be different"):
        ExperimentDefinition(**valid_experiment_definition_data)


def test_related_cves_domain_mismatch_rejected(valid_experiment_definition_data: dict) -> None:
    valid_experiment_definition_data["related_cves"][0]["domain"] = "TELECOM"
    with pytest.raises(ValidationError, match="outside the experiment's domain"):
        ExperimentDefinition(**valid_experiment_definition_data)


def test_duplicate_metrics_to_collect_rejected(valid_experiment_definition_data: dict) -> None:
    valid_experiment_definition_data["metrics_to_collect"] = ["block_rate", "block_rate"]
    with pytest.raises(ValidationError, match="duplicate"):
        ExperimentDefinition(**valid_experiment_definition_data)


def test_dataset_path_traversal_sequence_rejected(valid_experiment_definition_data: dict) -> None:
    valid_experiment_definition_data["dataset_path"] = "test_data/vpn/../../../etc/passwd"
    with pytest.raises(ValidationError, match="no '..' segments"):
        ExperimentDefinition(**valid_experiment_definition_data)


def test_experiment_id_is_frozen(valid_experiment_definition_data: dict) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    with pytest.raises(ValidationError):
        experiment.experiment_id = "ZC-VPN-EXP-998"
