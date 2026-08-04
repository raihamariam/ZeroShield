from datetime import UTC, datetime

import pytest

from zeroshield.models import CaseResult, ExperimentMetrics, ExperimentRun, PolicyDecision
from zeroshield.runners import RunOutcome

STARTED = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
COMPLETED = datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC)


@pytest.fixture
def evidence_run_outcome() -> RunOutcome:
    run = ExperimentRun(
        run_id="RUN-001",
        experiment_id="ZC-VPN-EXP-999",
        mode="baseline",
        dataset_hash="a" * 64,
        git_commit="abc1234",
        environment={"python_version": "3.12.10"},
        started_at=STARTED,
        completed_at=COMPLETED,
        status="completed",
    )
    case_results = [
        CaseResult(
            run_id="RUN-001",
            case_id="TC-001",
            decision="accepted",
            parser_reached=True,
            errored=False,
            logged=False,
            latency_ms=1.5,
        )
    ]
    return RunOutcome(run=run, strategy_id="weak_schema_length_baseline", case_results=case_results)


@pytest.fixture
def evidence_metrics() -> ExperimentMetrics:
    return ExperimentMetrics(
        run_id="RUN-001",
        processing_success_rate=1.0,
        block_rate=0.0,
        valid_acceptance_rate=1.0,
        false_positive_rate=0.0,
        false_negative_rate=1.0,
        parser_reach_rate=1.0,
        mean_latency_ms=1.5,
        log_completeness_rate=0.0,
        calculated_at=COMPLETED,
        calculation_version="1.0.0",
    )


@pytest.fixture
def evidence_policy_decision() -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        evaluated_at=STARTED,
        rule_results={"SAFE-001": True, "SAFE-002": True, "SAFE-003": True, "SAFE-004": True},
        reasons=[],
        policy_version="1.0.0",
    )
