from datetime import UTC, datetime

import pytest


@pytest.fixture
def valid_policy_decision_data() -> dict:
    return {
        "allowed": True,
        "evaluated_at": datetime(2026, 7, 13, 12, 0, 0, tzinfo=UTC),
        "rule_results": {"SAFE-001": True, "SAFE-002": True},
        "reasons": [],
        "policy_version": "1.0.0",
    }


@pytest.fixture
def valid_experiment_metrics_data() -> dict:
    return {
        "run_id": "RUN-001",
        "processing_success_rate": 1.0,
        "block_rate": 0.95,
        "valid_acceptance_rate": 0.99,
        "false_positive_rate": 0.01,
        "false_negative_rate": 0.02,
        "parser_reach_rate": 0.1,
        "mean_latency_ms": 12.5,
        "log_completeness_rate": 1.0,
        "calculated_at": datetime(2026, 7, 13, 12, 5, 0, tzinfo=UTC),
        "calculation_version": "1.0.0",
    }
