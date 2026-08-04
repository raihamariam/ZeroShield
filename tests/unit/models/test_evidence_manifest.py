from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from zeroshield.models import EvidenceManifest


def _base_manifest_data(metrics_data: dict, policy_data: dict) -> dict:
    started = datetime(2026, 7, 13, 12, 0, 0, tzinfo=UTC)
    return {
        "manifest_version": "1.0.0",
        "experiment_id": "ZC-VPN-EXP-999",
        "experiment_version": "1.0.0",
        "run_id": "RUN-001",
        "mode": "baseline",
        "test_set_id": "vpn-pre-auth-v1",
        "test_set_sha256": "b" * 64,
        "git_commit": "abc1234",
        "started_at": started,
        "completed_at": started + timedelta(seconds=10),
        "strategy_id": "weak_schema_length_baseline",
        "metrics": metrics_data,
        "artefact_paths": {
            "baseline_results": "evidence/ZC-VPN-EXP-999/RUN-001/baseline_results.json"
        },
        "safety_decision": policy_data,
        "review_status": "draft",
        "manifest_sha256": "c" * 64,
    }


def test_valid_evidence_manifest_parses(
    valid_experiment_metrics_data: dict, valid_policy_decision_data: dict
) -> None:
    data = _base_manifest_data(valid_experiment_metrics_data, valid_policy_decision_data)
    manifest = EvidenceManifest(**data)
    assert manifest.run_id == "RUN-001"
    assert manifest.container_image_digest is None


def test_completed_before_started_rejected(
    valid_experiment_metrics_data: dict, valid_policy_decision_data: dict
) -> None:
    data = _base_manifest_data(valid_experiment_metrics_data, valid_policy_decision_data)
    data["completed_at"] = data["started_at"] - timedelta(seconds=5)
    with pytest.raises(ValidationError, match="cannot be earlier"):
        EvidenceManifest(**data)


def test_metrics_run_id_mismatch_rejected(
    valid_experiment_metrics_data: dict, valid_policy_decision_data: dict
) -> None:
    data = _base_manifest_data(valid_experiment_metrics_data, valid_policy_decision_data)
    data["run_id"] = "RUN-002"
    with pytest.raises(ValidationError, match="metrics.run_id must match"):
        EvidenceManifest(**data)


def test_absolute_artefact_path_rejected(
    valid_experiment_metrics_data: dict, valid_policy_decision_data: dict
) -> None:
    data = _base_manifest_data(valid_experiment_metrics_data, valid_policy_decision_data)
    data["artefact_paths"] = {"baseline_results": "/absolute/path.json"}
    with pytest.raises(ValidationError, match="must be relative paths"):
        EvidenceManifest(**data)
