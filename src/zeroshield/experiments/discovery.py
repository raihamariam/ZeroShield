"""Discover ExperimentDefinition files in a directory, per SRS FR-001..004.

ExperimentDefinition is the sole source of truth for what counts as a valid,
runnable experiment. This module only scans for and parses candidate files -
it does not change approval status, run anything, or duplicate any validation
rule beyond what ExperimentDefinition itself already enforces.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from zeroshield.models import ExperimentDefinition


@dataclass(frozen=True)
class ExperimentDiscoveryError:
    path: Path
    reason: str


@dataclass(frozen=True)
class ExperimentDiscoveryResult:
    experiments: list[ExperimentDefinition]
    skipped: list[ExperimentDiscoveryError]


def discover_experiments(directory: Path) -> ExperimentDiscoveryResult:
    """Load every *.json file in directory that parses as a valid ExperimentDefinition.

    Files that are not valid JSON or fail ExperimentDefinition's schema validation
    are reported in `skipped` with a reason, rather than silently dropped.
    """
    if not directory.is_dir():
        return ExperimentDiscoveryResult(experiments=[], skipped=[])

    experiments: list[ExperimentDefinition] = []
    skipped: list[ExperimentDiscoveryError] = []

    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            skipped.append(ExperimentDiscoveryError(path=path, reason=f"invalid JSON: {exc}"))
            continue
        try:
            experiments.append(ExperimentDefinition.model_validate(raw))
        except ValidationError as exc:
            skipped.append(
                ExperimentDiscoveryError(path=path, reason=f"schema validation failed: {exc}")
            )

    return ExperimentDiscoveryResult(experiments=experiments, skipped=skipped)
