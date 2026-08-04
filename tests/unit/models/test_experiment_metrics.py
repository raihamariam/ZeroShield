import pytest
from pydantic import ValidationError

from zeroshield.models import ExperimentMetrics


def test_valid_experiment_metrics_parses(valid_experiment_metrics_data: dict) -> None:
    metrics = ExperimentMetrics(**valid_experiment_metrics_data)
    assert metrics.run_id == "RUN-001"


def test_rate_out_of_range_rejected(valid_experiment_metrics_data: dict) -> None:
    valid_experiment_metrics_data["block_rate"] = 1.5
    with pytest.raises(ValidationError, match="block_rate"):
        ExperimentMetrics(**valid_experiment_metrics_data)


def test_negative_latency_rejected(valid_experiment_metrics_data: dict) -> None:
    valid_experiment_metrics_data["mean_latency_ms"] = -1.0
    with pytest.raises(ValidationError, match="mean_latency_ms"):
        ExperimentMetrics(**valid_experiment_metrics_data)


def test_processing_success_rate_out_of_range_rejected(valid_experiment_metrics_data: dict) -> None:
    valid_experiment_metrics_data["processing_success_rate"] = 1.5
    with pytest.raises(ValidationError, match="processing_success_rate"):
        ExperimentMetrics(**valid_experiment_metrics_data)
