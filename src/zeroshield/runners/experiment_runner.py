import platform
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.models import (
    CaseResult,
    Decision,
    ExperimentDefinition,
    ExperimentRun,
    PolicyDecision,
    RunMode,
    RunStatus,
    TestCase,
)
from zeroshield.policies import ExecutionContext, SafetyPolicy
from zeroshield.strategies import ProcessingStrategy


class PolicyRefusalError(Exception):
    """Raised when SafetyPolicy refuses to allow an experiment run, per FR-011/AC-09."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__("experiment run refused by safety policy: " + "; ".join(decision.reasons))
        self.decision = decision


@dataclass(frozen=True)
class RunOutcome:
    run: ExperimentRun
    strategy_id: str
    case_results: list[CaseResult]


@dataclass(frozen=True)
class ExperimentExecutionResult:
    baseline: RunOutcome
    mitigation: RunOutcome
    safety_decision: PolicyDecision


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_environment() -> dict[str, str]:
    return {"python_version": platform.python_version()}


class ExperimentRunner:
    """Infrastructure-independent runner: executes baseline and mitigation over one dataset, per FR-006."""

    def __init__(self, safety_policy: SafetyPolicy | None = None) -> None:
        self._safety_policy = safety_policy or SafetyPolicy()

    def run(
        self,
        experiment: ExperimentDefinition,
        dataset_path: Path,
        *,
        baseline: ProcessingStrategy,
        mitigation: ProcessingStrategy,
        baseline_run_id: str,
        mitigation_run_id: str,
        git_commit: str,
        environment: dict[str, str] | None = None,
        execution_context: ExecutionContext = ExecutionContext.EXPERIMENT_RUN,
        clock: Callable[[], datetime] = _utc_now,
    ) -> ExperimentExecutionResult:
        decision = self._safety_policy.evaluate(
            experiment, execution_context=execution_context, clock=clock
        )
        if not decision.allowed:
            raise PolicyRefusalError(decision)

        if baseline.strategy_id != experiment.baseline_strategy:
            raise ValueError(
                f"baseline strategy_id '{baseline.strategy_id}' does not match experiment's "
                f"declared baseline_strategy '{experiment.baseline_strategy}'"
            )
        if mitigation.strategy_id != experiment.mitigation_strategy:
            raise ValueError(
                f"mitigation strategy_id '{mitigation.strategy_id}' does not match experiment's "
                f"declared mitigation_strategy '{experiment.mitigation_strategy}'"
            )

        test_set, dataset_hash = load_test_set(dataset_path)
        if test_set.domain != experiment.domain:
            raise ValueError(
                f"dataset domain '{test_set.domain.value}' does not match experiment domain "
                f"'{experiment.domain.value}'"
            )

        env = environment or _default_environment()

        baseline_outcome = self._execute_mode(
            strategy=baseline,
            cases=test_set.cases,
            experiment_id=experiment.experiment_id,
            run_id=baseline_run_id,
            mode=RunMode.BASELINE,
            dataset_hash=dataset_hash,
            git_commit=git_commit,
            environment=env,
            clock=clock,
        )
        mitigation_outcome = self._execute_mode(
            strategy=mitigation,
            cases=test_set.cases,
            experiment_id=experiment.experiment_id,
            run_id=mitigation_run_id,
            mode=RunMode.MITIGATED,
            dataset_hash=dataset_hash,
            git_commit=git_commit,
            environment=env,
            clock=clock,
        )

        return ExperimentExecutionResult(
            baseline=baseline_outcome, mitigation=mitigation_outcome, safety_decision=decision
        )

    def _execute_mode(
        self,
        *,
        strategy: ProcessingStrategy,
        cases: list[TestCase],
        experiment_id: str,
        run_id: str,
        mode: RunMode,
        dataset_hash: str,
        git_commit: str,
        environment: dict[str, str],
        clock: Callable[[], datetime],
    ) -> RunOutcome:
        started_at = clock()
        case_results = [self._execute_case(strategy=strategy, run_id=run_id, case=c) for c in cases]
        completed_at = clock()

        run = ExperimentRun(
            run_id=run_id,
            experiment_id=experiment_id,
            mode=mode,
            dataset_hash=dataset_hash,
            git_commit=git_commit,
            environment=environment,
            started_at=started_at,
            completed_at=completed_at,
            status=RunStatus.COMPLETED,
        )
        return RunOutcome(run=run, strategy_id=strategy.strategy_id, case_results=case_results)

    @staticmethod
    def _execute_case(*, strategy: ProcessingStrategy, run_id: str, case: TestCase) -> CaseResult:
        start = time.perf_counter()
        try:
            outcome = strategy.process(case.input_data)
        except Exception as exc:  # noqa: BLE001 - isolate any strategy failure so the run still completes (NFR-005)
            latency_ms = (time.perf_counter() - start) * 1000
            message = str(exc) or exc.__class__.__name__
            return CaseResult(
                run_id=run_id,
                case_id=case.case_id,
                decision=Decision.BLOCKED,
                parser_reached=False,
                errored=True,
                error_message=message,
                logged=True,
                latency_ms=latency_ms,
            )

        latency_ms = (time.perf_counter() - start) * 1000
        return CaseResult(
            run_id=run_id,
            case_id=case.case_id,
            decision=outcome.decision,
            parser_reached=outcome.parser_reached,
            errored=outcome.errored,
            error_message=outcome.error_message,
            logged=outcome.logged,
            latency_ms=latency_ms,
        )
