"""Verifies internal/unexpected failures never leak a traceback or server filesystem
details to the client, even when the underlying evidence is genuinely corrupted."""

import json
from pathlib import Path

from fastapi.testclient import TestClient


def _write_dangling_comparison(results_root: Path, experiment_id: str) -> None:
    """Writes a comparison.json that references run IDs whose manifest.json was never
    created - a realistic corrupted/incomplete-evidence scenario that makes
    experiment_service.load_latest_evidence raise an uncaught FileNotFoundError deep
    inside LocalEvidenceRepository.load_manifest."""
    metrics = {
        "run_id": "RUN-001",
        "processing_success_rate": 1.0,
        "block_rate": 0.0,
        "valid_acceptance_rate": 1.0,
        "false_positive_rate": 0.0,
        "false_negative_rate": 1.0,
        "parser_reach_rate": 1.0,
        "mean_latency_ms": 0.01,
        "log_completeness_rate": 0.0,
        "calculated_at": "2026-01-01T00:00:00Z",
        "calculation_version": "1.0.0",
    }
    mitigation_metrics = {**metrics, "run_id": "RUN-002", "block_rate": 1.0, "false_negative_rate": 0.0}
    payload = {
        "experiment_id": experiment_id,
        "baseline_run_id": "RUN-001",
        "mitigation_run_id": "RUN-002",
        "total_cases": 22,
        "baseline_metrics": metrics,
        "mitigation_metrics": mitigation_metrics,
        "block_rate_improvement": 1.0,
        "latency_overhead_ms": 0.0,
        "limitations": ["x"],
        "generated_at": "2026-01-01T00:00:00Z",
    }
    exp_dir = results_root / experiment_id
    exp_dir.mkdir(parents=True)
    (exp_dir / "comparison.json").write_text(json.dumps(payload), encoding="utf-8")


def test_results_with_corrupted_evidence_returns_generic_500(
    client: TestClient, results_root: Path
) -> None:
    _write_dangling_comparison(results_root, "ZC-VPN-EXP-001")

    response = client.get("/experiments/ZC-VPN-EXP-001/results")

    assert response.status_code == 500
    assert response.json() == {"error": "internal_error", "detail": "an internal error occurred"}
    assert "Traceback" not in response.text
    assert "raise" not in response.text
    assert str(Path.cwd()) not in response.text
    assert ".py" not in response.text


def test_evidence_with_corrupted_evidence_returns_generic_500(
    client: TestClient, results_root: Path
) -> None:
    _write_dangling_comparison(results_root, "ZC-VPN-EXP-001")

    response = client.get("/experiments/ZC-VPN-EXP-001/evidence")

    assert response.status_code == 500
    assert response.json() == {"error": "internal_error", "detail": "an internal error occurred"}
    assert "Traceback" not in response.text
