"""Step 10: sandbox timeout/cleanup, forbidden arbitrary executor."""

import socket
import time
from typing import Any

import pytest

from zeroshield.models.enums import Decision
from zeroshield.sandbox import (
    SandboxExecutor,
    SandboxForbiddenExecutorError,
    SandboxLimits,
    SandboxNetworkDeniedError,
    SandboxTimeoutError,
    sandbox_workspace,
)
from zeroshield.strategies.base import ProcessingStrategy
from zeroshield.strategies.outcome import StrategyOutcome
from zeroshield.strategies.vpn.weak_baseline import WeakSchemaLengthBaseline


class _SlowStrategy(ProcessingStrategy):
    strategy_id = "slow_test_strategy"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        time.sleep(2)
        return StrategyOutcome(decision=Decision.ACCEPTED, parser_reached=True)


class _NetworkStrategy(ProcessingStrategy):
    strategy_id = "network_test_strategy"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        socket.socket()
        return StrategyOutcome(decision=Decision.ACCEPTED, parser_reached=True)


class _ErroringStrategy(ProcessingStrategy):
    strategy_id = "erroring_test_strategy"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        raise RuntimeError("boom")


def test_allow_listed_strategy_executes_normally() -> None:
    executor = SandboxExecutor(allowed_strategy_ids=frozenset({"weak_schema_length_baseline"}))
    outcome = executor.execute(WeakSchemaLengthBaseline(), {"method": "GET", "path": "/x"})
    assert outcome.decision == Decision.ACCEPTED


def test_non_allow_listed_strategy_is_forbidden() -> None:
    executor = SandboxExecutor(allowed_strategy_ids=frozenset({"weak_schema_length_baseline"}))
    with pytest.raises(SandboxForbiddenExecutorError, match="not allow-listed"):
        executor.execute(_SlowStrategy(), {})


def test_no_allow_list_means_any_registered_strategy_class_runs() -> None:
    """allowed_strategy_ids=None (the default) is an explicit opt-out of the
    allow-list layer, used only by callers that have already allow-listed
    elsewhere - never the case for a domain-pack-scoped sandbox."""
    executor = SandboxExecutor()
    outcome = executor.execute(WeakSchemaLengthBaseline(), {"method": "GET", "path": "/x"})
    assert outcome.decision == Decision.ACCEPTED


def test_strategy_exceeding_timeout_raises_sandbox_timeout_error() -> None:
    executor = SandboxExecutor()
    with pytest.raises(SandboxTimeoutError, match="exceeded"):
        executor.execute(_SlowStrategy(), {}, limits=SandboxLimits(timeout_seconds=0.2))


def test_network_access_denied_by_default() -> None:
    executor = SandboxExecutor()
    with pytest.raises(SandboxNetworkDeniedError):
        executor.execute(_NetworkStrategy(), {}, limits=SandboxLimits(timeout_seconds=2.0))


def test_network_access_allowed_when_explicitly_enabled() -> None:
    executor = SandboxExecutor()
    outcome = executor.execute(
        _NetworkStrategy(), {}, limits=SandboxLimits(timeout_seconds=2.0, network_enabled=True)
    )
    assert outcome.decision == Decision.ACCEPTED


def test_socket_restored_after_sandbox_execution_exits() -> None:
    original = socket.socket
    executor = SandboxExecutor()
    with pytest.raises(SandboxNetworkDeniedError):
        executor.execute(_NetworkStrategy(), {}, limits=SandboxLimits(timeout_seconds=2.0))
    assert socket.socket is original
    s = socket.socket()
    s.close()


def test_socket_restored_even_after_timeout() -> None:
    original = socket.socket
    executor = SandboxExecutor()
    with pytest.raises(SandboxTimeoutError):
        executor.execute(_SlowStrategy(), {}, limits=SandboxLimits(timeout_seconds=0.1))
    assert socket.socket is original


def test_strategy_exception_propagates_uncaught_by_sandbox() -> None:
    """The sandbox only enforces allow-listing/timeout/network/resources - it
    never swallows a strategy's own exception (ExperimentRunner._execute_case
    is the layer that already converts a raised exception into a BLOCKED+
    errored CaseResult, per Phase 1/NFR-005 - unchanged by this phase)."""
    executor = SandboxExecutor()
    with pytest.raises(RuntimeError, match="boom"):
        executor.execute(_ErroringStrategy(), {})


def test_sandbox_workspace_directory_exists_during_and_removed_after() -> None:
    captured_path = None
    with sandbox_workspace() as workspace:
        captured_path = workspace
        assert workspace.is_dir()
        (workspace / "artifact.txt").write_text("evidence", encoding="utf-8")
    assert not captured_path.exists()


def test_sandbox_workspace_cleaned_up_even_on_exception() -> None:
    captured_path = None
    with pytest.raises(ValueError), sandbox_workspace() as workspace:
        captured_path = workspace
        raise ValueError("simulated failure inside workspace")
    assert not captured_path.exists()
