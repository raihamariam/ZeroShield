"""Thin, dashboard-facing service layer over the existing ZeroShield Core.

Every function here only loads input, calls existing core functionality
(experiments discovery/policies/orchestration/repositories/exports), and
returns plain dataclasses for Streamlit to render. No safety, metric,
strategy, or evidence logic is re-implemented here - this module is
presentation glue, exactly like zeroshield.cli.commands is for the CLI.
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zeroshield.datasets import load_test_set
from zeroshield.experiments import ExperimentDiscoveryResult, discover_experiments
from zeroshield.exports import save_overleaf_export
from zeroshield.models import (
    CaseResult,
    ComparisonReport,
    Decision,
    EvidenceManifest,
    ExperimentDefinition,
    PolicyDecision,
    TestCase,
    TestCaseCategory,
)
from zeroshield.orchestration import execute_and_generate_evidence
from zeroshield.policies import ExecutionContext, SafetyPolicy
from zeroshield.repositories import LocalEvidenceRepository
from zeroshield.strategies.registry import UnknownStrategyError, resolve_strategy


class DashboardError(Exception):
    """Raised for any dashboard-detected failure that isn't already a core exception."""


def list_experiments(experiments_dir: Path) -> ExperimentDiscoveryResult:
    """Discover valid ExperimentDefinition files. Thin wrapper over experiments.discovery."""
    return discover_experiments(experiments_dir)


@dataclass(frozen=True)
class SafetyCheck:
    decision: PolicyDecision
    execution_context: ExecutionContext


def check_safety(
    experiment: ExperimentDefinition, *, execution_context: ExecutionContext
) -> SafetyCheck:
    """Evaluate the existing SafetyPolicy. Never bypassed, never overridden here."""
    decision = SafetyPolicy().evaluate(experiment, execution_context=execution_context)
    return SafetyCheck(decision=decision, execution_context=execution_context)


@dataclass(frozen=True)
class RunOutcomeSummary:
    comparison_report: ComparisonReport
    baseline_manifest_path: Path
    mitigation_manifest_path: Path
    results_dir: Path


def run_experiment(
    experiment: ExperimentDefinition,
    *,
    execution_context: ExecutionContext,
    results_root: Path,
    git_commit: str = "0000000",
) -> RunOutcomeSummary:
    """Run baseline+mitigation and persist evidence via the existing orchestration layer.

    Raises DashboardError for dataset/strategy resolution problems, and lets
    zeroshield.runners.PolicyRefusalError propagate unchanged - the safety
    gate inside ExperimentRunner.run() is never bypassed here.
    """
    dataset_path = Path.cwd() / experiment.dataset_path
    if not dataset_path.is_file():
        raise DashboardError(f"dataset not found: {dataset_path}")

    try:
        baseline = resolve_strategy(experiment.baseline_strategy)
        mitigation = resolve_strategy(experiment.mitigation_strategy)
    except UnknownStrategyError as exc:
        raise DashboardError(str(exc)) from exc

    stamp = int(time.time() * 1000)
    baseline_run_id = f"RUN-{stamp}01"
    mitigation_run_id = f"RUN-{stamp}02"

    repo = LocalEvidenceRepository(results_root)
    result = execute_and_generate_evidence(
        experiment,
        dataset_path,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id=baseline_run_id,
        mitigation_run_id=mitigation_run_id,
        git_commit=git_commit,
        evidence_repository=repo,
        execution_context=execution_context,
    )
    return RunOutcomeSummary(
        comparison_report=result.comparison_report,
        baseline_manifest_path=result.baseline_manifest_path,
        mitigation_manifest_path=result.mitigation_manifest_path,
        results_dir=results_root / experiment.experiment_id,
    )


@dataclass(frozen=True)
class CaseComparison:
    case_id: str
    test_case: TestCase | None  # None only if the original dataset could not be re-located
    baseline: CaseResult
    mitigation: CaseResult


@dataclass(frozen=True)
class CaseCategoryBreakdown:
    valid_count: int
    malformed_count: int
    boundary_count: int
    baseline_malformed_block_rate: float | None
    mitigation_malformed_block_rate: float | None


@dataclass(frozen=True)
class EvidenceView:
    experiment_id: str
    baseline_manifest: EvidenceManifest
    mitigation_manifest: EvidenceManifest
    comparison: ComparisonReport
    case_comparisons: list[CaseComparison]
    results_dir: Path
    dataset_note: str | None


def _read_json_artefact(run_dir: Path, manifest: EvidenceManifest, name: str) -> Any:
    path = run_dir / manifest.artefact_paths[name]
    return json.loads(path.read_text(encoding="utf-8"))


def load_latest_evidence(experiment_id: str, results_root: Path) -> EvidenceView | None:
    """Load the most recently generated comparison + both run manifests for an experiment.

    Reads only already-persisted evidence (comparison.json, manifest.json,
    results.json, dataset_manifest.json) through the existing
    LocalEvidenceRepository and each manifest's own artefact_paths. No metric
    or safety decision is recomputed here; case-level detail is a plain join
    of already-persisted CaseResult and TestCase records by case_id.
    """
    comparison_path = results_root / experiment_id / "comparison.json"
    if not comparison_path.is_file():
        return None
    comparison = ComparisonReport.model_validate_json(comparison_path.read_text(encoding="utf-8"))

    repo = LocalEvidenceRepository(results_root)
    baseline_manifest = repo.load_manifest(experiment_id, comparison.baseline_run_id)
    mitigation_manifest = repo.load_manifest(experiment_id, comparison.mitigation_run_id)

    baseline_dir = results_root / experiment_id / comparison.baseline_run_id
    mitigation_dir = results_root / experiment_id / comparison.mitigation_run_id

    baseline_results = [
        CaseResult.model_validate(r)
        for r in _read_json_artefact(baseline_dir, baseline_manifest, "results")
    ]
    mitigation_by_case = {
        r["case_id"]: CaseResult.model_validate(r)
        for r in _read_json_artefact(mitigation_dir, mitigation_manifest, "results")
    }

    dataset_note: str | None = None
    test_cases_by_id: dict[str, TestCase] = {}
    try:
        dataset_manifest_raw = _read_json_artefact(baseline_dir, baseline_manifest, "dataset_manifest")
        dataset_path = Path.cwd() / str(dataset_manifest_raw["dataset_path"])
        test_set, _ = load_test_set(dataset_path)
        test_cases_by_id = {tc.case_id: tc for tc in test_set.cases}
    except (FileNotFoundError, KeyError, ValueError) as exc:
        dataset_note = f"original dataset could not be re-loaded for per-case detail: {exc}"

    case_comparisons = []
    for baseline_result in baseline_results:
        mitigation_result = mitigation_by_case.get(baseline_result.case_id)
        if mitigation_result is None:
            continue
        case_comparisons.append(
            CaseComparison(
                case_id=baseline_result.case_id,
                test_case=test_cases_by_id.get(baseline_result.case_id),
                baseline=baseline_result,
                mitigation=mitigation_result,
            )
        )

    return EvidenceView(
        experiment_id=experiment_id,
        baseline_manifest=baseline_manifest,
        mitigation_manifest=mitigation_manifest,
        comparison=comparison,
        case_comparisons=case_comparisons,
        results_dir=results_root / experiment_id,
        dataset_note=dataset_note,
    )


def summarise_case_categories(case_comparisons: list[CaseComparison]) -> CaseCategoryBreakdown:
    """Count cases by TestCaseCategory and the malformed-only block rate, per side.

    Pure counting/filtering over already-persisted CaseResult/TestCase records
    - no decision is made or recomputed here.
    """
    known = [c for c in case_comparisons if c.test_case is not None]
    valid_count = sum(1 for c in known if c.test_case is not None and c.test_case.category == TestCaseCategory.VALID)
    malformed = [c for c in known if c.test_case is not None and c.test_case.category == TestCaseCategory.MALFORMED]
    boundary_count = sum(
        1 for c in known if c.test_case is not None and c.test_case.category == TestCaseCategory.BOUNDARY
    )

    if malformed:
        baseline_rate: float | None = sum(
            1 for c in malformed if c.baseline.decision == Decision.BLOCKED
        ) / len(malformed)
        mitigation_rate: float | None = sum(
            1 for c in malformed if c.mitigation.decision == Decision.BLOCKED
        ) / len(malformed)
    else:
        baseline_rate = None
        mitigation_rate = None

    return CaseCategoryBreakdown(
        valid_count=valid_count,
        malformed_count=len(malformed),
        boundary_count=boundary_count,
        baseline_malformed_block_rate=baseline_rate,
        mitigation_malformed_block_rate=mitigation_rate,
    )


def generate_overleaf_export(
    experiment: ExperimentDefinition, comparison: ComparisonReport, export_root: Path
) -> Path:
    """Generate the VPN/Telecom Overleaf export. Thin wrapper over the existing exporter."""
    return save_overleaf_export(export_root, comparison, experiment)
