"""Thin command implementations for the zeroshield CLI.

Every function here only loads input, calls existing core functionality
(models/policies/runners/orchestration/repositories/strategies.registry),
and prints/reports the result. No validation, safety, or research logic is
implemented here.
"""

import json
import time
from pathlib import Path

from pydantic import ValidationError

from zeroshield.models import ComparisonReport, ExperimentDefinition
from zeroshield.orchestration import execute_and_generate_evidence
from zeroshield.policies import ExecutionContext, SafetyPolicy
from zeroshield.repositories import LocalEvidenceRepository, verify_manifest_integrity
from zeroshield.runners import PolicyRefusalError
from zeroshield.strategies.registry import UnknownStrategyError, resolve_strategy


class CliError(Exception):
    """Raised for any CLI-detected failure; main() converts this to a non-zero exit code."""


def _load_experiment(experiment_path: Path) -> ExperimentDefinition:
    if not experiment_path.is_file():
        raise CliError(f"experiment file not found: {experiment_path}")
    try:
        raw = json.loads(experiment_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CliError(f"experiment file is not valid JSON: {experiment_path} ({exc})") from exc
    try:
        return ExperimentDefinition(**raw)
    except ValidationError as exc:
        raise CliError(f"experiment failed schema validation:\n{exc}") from exc


def validate_experiment(experiment_path: Path, *, context: ExecutionContext) -> bool:
    """Load, schema-validate, and safety-evaluate an experiment. Never executes it."""
    print(f"Experiment file: {experiment_path}")
    try:
        experiment = _load_experiment(experiment_path)
    except CliError as exc:
        print(f"Schema validation: FAIL\n  {exc}")
        print("\nVALIDATION: FAIL")
        return False

    print(f"Experiment ID: {experiment.experiment_id}")
    print(f"Domain: {experiment.domain.value}")
    print("Schema validation: PASS (includes required research metadata)")

    dataset_path = Path.cwd() / experiment.dataset_path
    dataset_ok = dataset_path.is_file()
    print(f"Dataset ({experiment.dataset_path}): {'PASS' if dataset_ok else 'FAIL (not found)'}")

    decision = SafetyPolicy().evaluate(experiment, execution_context=context)
    print(f"Safety policy ({context.value}): {'PASS' if decision.allowed else 'FAIL'}")
    for reason in decision.reasons:
        print(f"  - {reason}")

    overall = dataset_ok and decision.allowed
    print(f"\nVALIDATION: {'PASS' if overall else 'FAIL'}")
    return overall


def run_experiment(
    experiment_path: Path,
    *,
    context: ExecutionContext,
    baseline_run_id: str | None,
    mitigation_run_id: str | None,
    git_commit: str,
    results_root: Path,
) -> bool:
    """Validate, safety-gate, execute baseline+mitigation, and persist evidence.

    Sequence: load -> schema validation -> (strategy resolution) -> safety
    evaluation (inside ExperimentRunner.run, before any case is processed) ->
    dataset load -> execution -> metrics -> evidence.
    """
    experiment = _load_experiment(experiment_path)
    print(f"Experiment: {experiment.experiment_id} (domain={experiment.domain.value})")

    dataset_path = Path.cwd() / experiment.dataset_path
    if not dataset_path.is_file():
        raise CliError(f"dataset not found: {dataset_path}")

    try:
        baseline = resolve_strategy(experiment.baseline_strategy)
        mitigation = resolve_strategy(experiment.mitigation_strategy)
    except UnknownStrategyError as exc:
        raise CliError(str(exc)) from exc

    if baseline_run_id is None or mitigation_run_id is None:
        stamp = int(time.time())
        baseline_run_id = baseline_run_id or f"RUN-{stamp}01"
        mitigation_run_id = mitigation_run_id or f"RUN-{stamp}02"

    repo = LocalEvidenceRepository(results_root)

    try:
        result = execute_and_generate_evidence(
            experiment,
            dataset_path,
            baseline=baseline,
            mitigation=mitigation,
            baseline_run_id=baseline_run_id,
            mitigation_run_id=mitigation_run_id,
            git_commit=git_commit,
            evidence_repository=repo,
            execution_context=context,
        )
    except PolicyRefusalError as exc:
        print(f"Safety decision: DENIED ({context.value})")
        for reason in exc.decision.reasons:
            print(f"  - {reason}")
        print("\nCOMPLETION: FAILED (refused by safety policy before execution)")
        return False

    print(f"Safety decision: ALLOWED ({context.value})")
    print(f"Cases: {len(result.execution.baseline.case_results)}")
    print(
        "Baseline status: "
        f"{result.execution.baseline.run.status.value} (run_id={baseline_run_id})"
    )
    print(
        "Mitigation status: "
        f"{result.execution.mitigation.run.status.value} (run_id={mitigation_run_id})"
    )

    bm = result.comparison_report.baseline_metrics
    mm = result.comparison_report.mitigation_metrics
    print("Key metrics:")
    print(f"  block_rate: baseline={bm.block_rate:.3f} mitigation={mm.block_rate:.3f}")
    print(
        "  valid_acceptance_rate: "
        f"baseline={bm.valid_acceptance_rate:.3f} mitigation={mm.valid_acceptance_rate:.3f}"
    )
    print(f"  block_rate_improvement: {result.comparison_report.block_rate_improvement:.3f}")
    print(f"Evidence output path: {result.baseline_manifest_path.parent.parent}")
    print("\nCOMPLETION: SUCCESS")
    return True


def compare_experiment(experiment_dir: Path) -> bool:
    """Load and display an already-generated comparison.json. Never re-runs anything."""
    comparison_path = experiment_dir / "comparison.json"
    if not comparison_path.is_file():
        raise CliError(f"comparison.json not found under {experiment_dir}")
    try:
        report = ComparisonReport.model_validate_json(comparison_path.read_text(encoding="utf-8"))
    except ValidationError as exc:
        raise CliError(f"comparison.json failed schema validation:\n{exc}") from exc

    print(f"Experiment: {report.experiment_id}")
    print(f"Baseline run: {report.baseline_run_id}  Mitigation run: {report.mitigation_run_id}")
    print(f"Total cases: {report.total_cases}")
    print(f"{'Metric':<26}{'Baseline':>12}{'Mitigation':>12}{'Difference':>12}")
    for field in (
        "processing_success_rate",
        "block_rate",
        "valid_acceptance_rate",
        "false_positive_rate",
        "false_negative_rate",
        "parser_reach_rate",
        "mean_latency_ms",
        "log_completeness_rate",
    ):
        b = getattr(report.baseline_metrics, field)
        m = getattr(report.mitigation_metrics, field)
        print(f"{field:<26}{b:>12.4f}{m:>12.4f}{m - b:>12.4f}")

    print(f"\nBlock-rate improvement: {report.block_rate_improvement:.4f}")
    print(f"Latency overhead (ms): {report.latency_overhead_ms:.4f}")
    print("\nLimitations:")
    for item in report.limitations:
        print(f"  - {item}")
    return True


def verify_evidence(run_dir: Path) -> bool:
    """Load a run's manifest and verify artefact presence + manifest integrity hash."""
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        raise CliError(f"run directory not found: {run_dir}")

    run_id = run_dir.name
    experiment_id = run_dir.parent.name
    root = run_dir.parent.parent

    repo = LocalEvidenceRepository(root)
    try:
        manifest = repo.load_manifest(experiment_id, run_id)
    except FileNotFoundError as exc:
        raise CliError(f"manifest.json not found under {run_dir}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"manifest.json is not valid JSON: {exc}") from exc
    except ValidationError as exc:
        raise CliError(f"manifest.json failed schema validation:\n{exc}") from exc

    print(f"Manifest: {run_dir / 'manifest.json'}")
    print(f"Experiment ID: {manifest.experiment_id}  Run ID: {manifest.run_id}  Mode: {manifest.mode.value}")

    ok = True

    if manifest.experiment_id != experiment_id:
        print(
            "Consistency: FAIL "
            f"(manifest experiment_id '{manifest.experiment_id}' != directory '{experiment_id}')"
        )
        ok = False
    if manifest.run_id != run_id:
        print(f"Consistency: FAIL (manifest run_id '{manifest.run_id}' != directory '{run_id}')")
        ok = False

    missing = [name for name, rel in manifest.artefact_paths.items() if not (run_dir / rel).is_file()]
    if missing:
        print(f"Artefact files: FAIL (missing: {missing})")
        ok = False
    else:
        print(f"Artefact files: PASS ({len(manifest.artefact_paths)} present)")

    integrity_ok = verify_manifest_integrity(manifest)
    print(f"Manifest integrity (SHA-256): {'PASS' if integrity_ok else 'FAIL (manifest may have been modified)'}")
    ok = ok and integrity_ok

    print(f"\nVERIFICATION: {'PASS' if ok else 'FAIL'}")
    return ok
