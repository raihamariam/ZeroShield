from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.metrics import calculate_metrics, compare
from zeroshield.models import ComparisonReport, ExperimentDefinition
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import EvidenceRepository, build_run_evidence
from zeroshield.runners import ExperimentExecutionResult, ExperimentRunner
from zeroshield.strategies import ProcessingStrategy


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ValidationResult:
    execution: ExperimentExecutionResult
    baseline_manifest_path: Path
    mitigation_manifest_path: Path
    comparison_path: Path
    comparison_report: ComparisonReport


def execute_and_generate_evidence(
    experiment: ExperimentDefinition,
    dataset_path: Path,
    *,
    baseline: ProcessingStrategy,
    mitigation: ProcessingStrategy,
    baseline_run_id: str,
    mitigation_run_id: str,
    git_commit: str,
    evidence_repository: EvidenceRepository,
    runner: ExperimentRunner | None = None,
    execution_context: ExecutionContext = ExecutionContext.EXPERIMENT_RUN,
    environment: dict[str, str] | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> ValidationResult:
    """Run baseline+mitigation, compute metrics/comparison, and persist evidence for both runs."""
    runner = runner or ExperimentRunner()
    test_set, _ = load_test_set(dataset_path)

    result = runner.run(
        experiment,
        dataset_path,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id=baseline_run_id,
        mitigation_run_id=mitigation_run_id,
        git_commit=git_commit,
        environment=environment,
        execution_context=execution_context,
        clock=clock,
    )

    baseline_metrics = calculate_metrics(
        baseline_run_id, result.baseline.case_results, test_set.cases, clock=clock
    )
    mitigation_metrics = calculate_metrics(
        mitigation_run_id, result.mitigation.case_results, test_set.cases, clock=clock
    )

    baseline_bundle = build_run_evidence(
        experiment, test_set.test_set_id, result.baseline, baseline_metrics, result.safety_decision
    )
    mitigation_bundle = build_run_evidence(
        experiment, test_set.test_set_id, result.mitigation, mitigation_metrics, result.safety_decision
    )

    report = compare(
        experiment.experiment_id,
        len(test_set.cases),
        baseline_metrics,
        mitigation_metrics,
        clock=clock,
    )

    baseline_dir = evidence_repository.save_run_evidence(baseline_bundle)
    mitigation_dir = evidence_repository.save_run_evidence(mitigation_bundle)
    comparison_path = evidence_repository.save_comparison(experiment.experiment_id, report)

    return ValidationResult(
        execution=result,
        baseline_manifest_path=baseline_dir / "manifest.json",
        mitigation_manifest_path=mitigation_dir / "manifest.json",
        comparison_path=comparison_path,
        comparison_report=report,
    )
